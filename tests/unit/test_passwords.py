from __future__ import annotations

import asyncio
import hashlib
from collections.abc import Iterator

import httpx
import pytest
from pytest_httpx import HTTPXMock

from pwned.client import HIBPError
from pwned.config import DEFAULT_USER_AGENT
from pwned.passwords import (
    BASE_URL,
    AsyncPwnedPasswordsClient,
    PwnedPasswordsClient,
    _hash_password,
    _md4,
    _ntlm_hash,
    _parse_range_response,
)

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


class TestHelpers:
    def test_hash_password_sha1(self) -> None:
        assert _hash_password("password", ntlm=False) == SHA1_PASSWORD

    def test_hash_password_ntlm(self) -> None:
        assert _hash_password("password", ntlm=True) == _ntlm_hash("password")

    @pytest.mark.parametrize(
        ("text", "expected"),
        [
            ("", {}),
            ("\n   \nNO_COLON_LINE\n", {}),
            (f"{SUFFIX}:5:extra\n", {}),
            (":5\n", {}),
            (f"{SUFFIX}:notanint\n", {}),
            (f"{SUFFIX}:0\nOTHER:-3\n", {}),
            (
                f"{SUFFIX.lower()}:123\n  0018a45c4d1def81644b54ab7f969b88d65:7  \r\n",
                {
                    SUFFIX: 123,
                    "0018A45C4D1DEF81644B54AB7F969B88D65": 7,
                },
            ),
            (f"{SUFFIX}:0\n{SUFFIX}:15\n{SUFFIX}:0\n", {SUFFIX: 15}),
        ],
    )
    def test_parse_range_response(self, text: str, expected: dict[str, int]) -> None:
        assert _parse_range_response(text) == expected


class TestClientOptionsAndLifecycle:
    def test_custom_timeout_and_proxy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        captured: dict[str, object] = {}
        real_client_cls = httpx.Client

        def fake_client(**kwargs: object) -> httpx.Client:
            captured.update(kwargs)
            return real_client_cls(**kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(httpx, "Client", fake_client)
        with PwnedPasswordsClient(
            user_agent="custom-ua",
            timeout=25.0,
            proxy="http://127.0.0.1:8888",
        ) as c:
            assert c._client.timeout == httpx.Timeout(25.0)
        assert captured == {
            "base_url": BASE_URL,
            "headers": {"User-Agent": "custom-ua"},
            "timeout": 25.0,
            "proxy": "http://127.0.0.1:8888",
        }

    def test_external_client_not_closed_on_close_or_exit(self, httpx_mock: HTTPXMock) -> None:
        ext_client = httpx.Client(base_url=BASE_URL)
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/{PREFIX}",
            text=f"{SUFFIX}:11\n",
        )
        with PwnedPasswordsClient(client=ext_client) as c:
            assert c.check_password("password") == 11
        assert not ext_client.is_closed
        c.close()
        assert not ext_client.is_closed
        ext_client.close()


class TestGetPasswordRange:
    def test_valid_prefix_normalized_and_parsed(
        self, client: PwnedPasswordsClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/{PREFIX}",
            text=RANGE_RESPONSE + "ABCDE00000000000000000000000000000F:0\n",
        )
        result = client.get_password_range(f"  {PREFIX.lower()}  ")
        assert result == {
            SUFFIX: 3861493,
            "0018A45C4D1DEF81644B54AB7F969B88D65": 1,
            "00D4F6E8FA6EECAD2A3AA415EEC418D38EC": 2,
        }

    def test_ntlm_and_pad_flags(self, client: PwnedPasswordsClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(
            url=httpx.URL(f"{BASE_URL}/range/{PREFIX}", params={"mode": "ntlm"}),
            text=f"{SUFFIX}:7\n",
        )
        result = client.get_password_range(PREFIX, ntlm=True, pad=True)
        assert result == {SUFFIX: 7}
        req = httpx_mock.get_request()
        assert req is not None
        assert req.headers["Add-Padding"] == "true"
        assert req.url.params["mode"] == "ntlm"

    @pytest.mark.parametrize(
        "bad_prefix",
        ["", "     ", "5BAA", "5BAA61", "5BAAG", "+1234", "1_234", "0x123"],
    )
    def test_invalid_prefix_raises_value_error(
        self, client: PwnedPasswordsClient, bad_prefix: str
    ) -> None:
        with pytest.raises(
            ValueError, match="Hash prefix must be exactly 5 hexadecimal characters"
        ):
            client.get_password_range(bad_prefix)

    def test_http_error_wrapped(self, client: PwnedPasswordsClient, httpx_mock: HTTPXMock) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/range/{PREFIX}", status_code=503)
        with pytest.raises(HIBPError, match="HTTP 503"):
            client.get_password_range(PREFIX)

    def test_network_error_wrapped(
        self, client: PwnedPasswordsClient, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_exception(
            httpx.ConnectError("connection failed"),
            url=f"{BASE_URL}/range/{PREFIX}",
        )
        with pytest.raises(HIBPError, match="Request failed"):
            client.get_password_range(PREFIX)


class TestIsPwned:
    @pytest.mark.parametrize(
        ("count", "threshold", "expected"),
        [
            (0, 1, False),
            (1, 1, True),
            (4, 5, False),
            (5, 5, True),
            (10, 5, True),
        ],
    )
    def test_threshold_comparison(
        self,
        client: PwnedPasswordsClient,
        httpx_mock: HTTPXMock,
        count: int,
        threshold: int,
        expected: bool,
    ) -> None:
        body = f"{SUFFIX}:{count}\n" if count > 0 else ""
        httpx_mock.add_response(url=f"{BASE_URL}/range/{PREFIX}", text=body)
        assert client.is_pwned("password", threshold=threshold) is expected

    def test_forwards_ntlm_and_pad(
        self, client: PwnedPasswordsClient, httpx_mock: HTTPXMock
    ) -> None:
        ntlm = _ntlm_hash("password")
        httpx_mock.add_response(
            url=httpx.URL(f"{BASE_URL}/range/{ntlm[:5]}", params={"mode": "ntlm"}),
            text=f"{ntlm[5:]}:3\n",
        )
        assert client.is_pwned("password", threshold=2, ntlm=True, pad=True) is True
        req = httpx_mock.get_request()
        assert req is not None
        assert req.headers["Add-Padding"] == "true"

    @pytest.mark.parametrize("bad_threshold", [0, -1, -100])
    def test_invalid_threshold_raises_value_error(
        self, client: PwnedPasswordsClient, bad_threshold: int
    ) -> None:
        with pytest.raises(ValueError, match="threshold must be at least 1"):
            client.is_pwned("password", threshold=bad_threshold)


class TestAsyncPwnedPasswordsClient:
    def test_context_manager_and_default_options(self, httpx_mock: HTTPXMock) -> None:
        async def run() -> None:
            httpx_mock.add_response(
                url=f"{BASE_URL}/range/{PREFIX}",
                text=f"{SUFFIX}:42\n",
            )
            async with AsyncPwnedPasswordsClient() as ac:
                assert await ac.check_password("password") == 42
                assert not ac._client.is_closed
            assert ac._client.is_closed
            req = httpx_mock.get_request()
            assert req is not None
            assert req.headers["User-Agent"] == DEFAULT_USER_AGENT

        asyncio.run(run())

    def test_custom_timeout_proxy_and_explicit_aclose(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        captured: dict[str, object] = {}
        real_async_cls = httpx.AsyncClient

        def fake_async_client(**kwargs: object) -> httpx.AsyncClient:
            captured.update(kwargs)
            return real_async_cls(**kwargs)  # type: ignore[arg-type]

        monkeypatch.setattr(httpx, "AsyncClient", fake_async_client)

        async def run() -> None:
            ac = AsyncPwnedPasswordsClient(
                user_agent="async-ua",
                timeout=15.0,
                proxy="http://127.0.0.1:8888",
            )
            assert ac._client.timeout == httpx.Timeout(15.0)
            await ac.aclose()
            assert ac._client.is_closed

        asyncio.run(run())
        assert captured == {
            "base_url": BASE_URL,
            "headers": {"User-Agent": "async-ua"},
            "timeout": 15.0,
            "proxy": "http://127.0.0.1:8888",
        }

    def test_external_async_client_not_closed(self, httpx_mock: HTTPXMock) -> None:
        async def run() -> None:
            ext_client = httpx.AsyncClient(base_url=BASE_URL)
            httpx_mock.add_response(
                url=f"{BASE_URL}/range/{PREFIX}",
                text=f"{SUFFIX}:9\n",
            )
            async with AsyncPwnedPasswordsClient(client=ext_client) as ac:
                assert await ac.check_password("password") == 9
            assert not ext_client.is_closed
            await ac.aclose()
            assert not ext_client.is_closed
            await ext_client.aclose()

        asyncio.run(run())

    def test_async_get_password_range(self, httpx_mock: HTTPXMock) -> None:
        async def run() -> None:
            httpx_mock.add_response(
                url=httpx.URL(f"{BASE_URL}/range/{PREFIX}", params={"mode": "ntlm"}),
                text=f"{SUFFIX}:12\nABCDE00000000000000000000000000000F:0\n",
            )
            async with AsyncPwnedPasswordsClient(user_agent="test-agent") as ac:
                result = await ac.get_password_range(f" {PREFIX.lower()} ", ntlm=True, pad=True)
                assert result == {SUFFIX: 12}
            req = httpx_mock.get_request()
            assert req is not None
            assert req.headers["Add-Padding"] == "true"

        asyncio.run(run())

    def test_async_get_password_range_invalid_prefix(self) -> None:
        async def run() -> None:
            async with AsyncPwnedPasswordsClient(user_agent="test-agent") as ac:
                with pytest.raises(
                    ValueError, match="Hash prefix must be exactly 5 hexadecimal characters"
                ):
                    await ac.get_password_range("INVALID")

        asyncio.run(run())

    def test_async_http_and_network_errors_wrapped(self, httpx_mock: HTTPXMock) -> None:
        async def run() -> None:
            httpx_mock.add_response(url=f"{BASE_URL}/range/{PREFIX}", status_code=500)
            httpx_mock.add_exception(
                httpx.ReadTimeout("timed out"),
                url=f"{BASE_URL}/range/{PREFIX}",
            )
            async with AsyncPwnedPasswordsClient(user_agent="test-agent") as ac:
                with pytest.raises(HIBPError, match="HTTP 500"):
                    await ac.get_password_range(PREFIX)
                with pytest.raises(HIBPError, match="Request failed"):
                    await ac.get_password_range(PREFIX)

        asyncio.run(run())

    def test_async_check_password_and_is_pwned(self, httpx_mock: HTTPXMock) -> None:
        async def run() -> None:
            ntlm = _ntlm_hash("password")
            httpx_mock.add_response(
                url=f"{BASE_URL}/range/{PREFIX}",
                text=f"{SUFFIX}:0\n",
            )
            httpx_mock.add_response(
                url=httpx.URL(f"{BASE_URL}/range/{ntlm[:5]}", params={"mode": "ntlm"}),
                text=f"{ntlm[5:]}:10\n",
            )
            httpx_mock.add_response(
                url=f"{BASE_URL}/range/{PREFIX}",
                text=f"{SUFFIX}:3\n",
            )
            async with AsyncPwnedPasswordsClient(user_agent="test-agent") as ac:
                assert await ac.check_password("password", pad=True) == 0
                assert await ac.check_password("password", ntlm=True) == 10
                assert await ac.is_pwned("password", threshold=3) is True
                with pytest.raises(ValueError, match="threshold must be at least 1"):
                    await ac.is_pwned("password", threshold=0)

        asyncio.run(run())
