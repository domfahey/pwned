from __future__ import annotations

import hashlib
import io
import json
import sys
from pathlib import Path
from typing import Any

import pytest
from pytest_httpx import HTTPXMock

from pwned import __version__
from pwned.audit import AuditEntry
from pwned.cache import ResponseCache
from pwned.mcp_server import JSONRPC_VERSION, MCP_PROTOCOL_VERSION, MCPServer, serve_stdio

SAMPLE_BREACH: dict[str, Any] = {
    "Name": "Adobe",
    "Title": "Adobe",
    "Domain": "adobe.com",
    "BreachDate": "2013-10-04",
    "AddedDate": "2013-12-04T00:00:00Z",
    "ModifiedDate": "2022-05-15T23:52:49Z",
    "PwnCount": 152445165,
    "Description": "In October 2013, 153 million Adobe accounts were breached.",
    "DataClasses": ["Email addresses", "Password hints", "Passwords", "Usernames"],
    "IsVerified": True,
    "IsFabricated": False,
    "IsSensitive": False,
    "IsRetired": False,
    "IsSpamList": False,
    "IsMalware": False,
    "IsSubscriptionFree": False,
    "IsStealerLog": False,
    "LogoPath": "https://haveibeenpwned.com/Content/Images/PwnedLogos/Adobe.png",
}

SECOND_BREACH: dict[str, Any] = {
    **SAMPLE_BREACH,
    "Name": "Dropbox",
    "Title": "Dropbox",
    "Domain": "dropbox.com",
    "PwnCount": 68648009,
}


def _sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def _call_tool(
    server: MCPServer,
    name: str,
    arguments: dict[str, Any] | None = None,
    *,
    req_id: int = 1,
) -> dict[str, Any]:
    params: dict[str, Any] = {"name": name}
    if arguments is not None:
        params["arguments"] = arguments
    resp = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "method": "tools/call",
            "params": params,
        }
    )
    assert resp is not None
    return resp


def _parse_tool_result(resp: dict[str, Any]) -> tuple[bool, Any]:
    result = resp["result"]
    assert len(result["content"]) == 1
    assert result["content"][0]["type"] == "text"
    text = result["content"][0]["text"]
    if result["isError"]:
        return True, text
    return False, json.loads(text)


def test_constants() -> None:
    assert MCP_PROTOCOL_VERSION == "2024-11-05"
    assert JSONRPC_VERSION == "2.0"


def test_handle_message_invalid_requests() -> None:
    server = MCPServer()

    for bad in ("not-a-dict", ["list"], None):
        resp = server.handle_message(bad)
        assert resp == {
            "jsonrpc": "2.0",
            "id": None,
            "error": {"code": -32600, "message": "Invalid Request"},
        }

    resp = server.handle_message({"jsonrpc": "1.0", "id": 7, "method": "ping"})
    assert resp == {
        "jsonrpc": "2.0",
        "id": 7,
        "error": {"code": -32600, "message": "Invalid Request"},
    }

    resp = server.handle_message({"jsonrpc": "2.0", "id": "abc", "method": 123})
    assert resp == {
        "jsonrpc": "2.0",
        "id": "abc",
        "error": {"code": -32600, "message": "Invalid Request"},
    }


def test_handle_message_initialize_ping_and_notifications() -> None:
    server = MCPServer()

    init_resp = server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "initialize"})
    assert init_resp == {
        "jsonrpc": "2.0",
        "id": 1,
        "result": {
            "protocolVersion": "2024-11-05",
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "pwned", "version": __version__},
        },
    }

    assert server.handle_message({"jsonrpc": "2.0", "method": "notifications/initialized"}) is None
    assert (
        server.handle_message({"jsonrpc": "2.0", "id": 9, "method": "notifications/initialized"})
        is None
    )
    assert server.handle_message({"jsonrpc": "2.0", "method": "notifications/cancelled"}) is None
    assert server.handle_message({"jsonrpc": "2.0", "method": "unknown/notify"}) is None

    ping_resp = server.handle_message({"jsonrpc": "2.0", "id": 2, "method": "ping"})
    assert ping_resp == {"jsonrpc": "2.0", "id": 2, "result": {}}

    unknown_resp = server.handle_message({"jsonrpc": "2.0", "id": 3, "method": "unknown/method"})
    assert unknown_resp == {
        "jsonrpc": "2.0",
        "id": 3,
        "error": {"code": -32601, "message": "Method not found"},
    }


def test_tools_list_exposes_all_expected_tools() -> None:
    server = MCPServer()
    resp = server.handle_message({"jsonrpc": "2.0", "id": 1, "method": "tools/list"})
    assert resp is not None
    tools = resp["result"]["tools"]
    names = [tool["name"] for tool in tools]
    assert names == [
        "check_password_hash",
        "audit_vault",
        "diff_baseline",
        "lookup_breach",
        "check_account_range",
    ]
    for tool in tools:
        assert isinstance(tool["description"], str) and tool["description"]
        schema = tool["inputSchema"]
        assert schema["type"] == "object"
        assert isinstance(schema["properties"], dict)

    audit_tool = next(tool for tool in tools if tool["name"] == "audit_vault")
    check_breaches_prop = audit_tool["inputSchema"]["properties"]["check_breaches"]
    assert check_breaches_prop["type"] == "boolean"
    assert check_breaches_prop["default"] is False
    assert "Correlate vault entry domains" in check_breaches_prop["description"]


def test_tools_call_invalid_params_and_unknown_tool() -> None:
    server = MCPServer()

    bad_params_cases: list[Any] = [
        None,
        "bad",
        [],
        {"name": 123},
        {"name": "ping", "arguments": []},
    ]
    for bad_params in bad_params_cases:
        resp = server.handle_message(
            {"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": bad_params}
        )
        assert resp is not None
        assert resp["error"]["code"] == -32602

    resp = _call_tool(server, "nonexistent_tool", {}, req_id=11)
    assert resp == {
        "jsonrpc": "2.0",
        "id": 11,
        "error": {"code": -32602, "message": "Unknown tool: nonexistent_tool"},
    }


def test_check_password_hash_online_sha1_and_ntlm(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    digest = _sha1_hex("password123")
    prefix, suffix = digest[:5], digest[5:]
    httpx_mock.add_response(
        url=f"https://api.pwnedpasswords.com/range/{prefix}",
        text=f"{suffix}:42\r\n{'0' * 35}:1\r\n",
    )

    cache = ResponseCache(tmp_path / "cache", ttl_seconds=300)
    server = MCPServer(user_agent="test-mcp", cache=cache)

    resp = _call_tool(server, "check_password_hash", {"hash_hex": digest.lower()})
    is_err, payload = _parse_tool_result(resp)
    assert not is_err
    assert payload == {"count": 42, "pwned": True, "threshold": 1, "source": "online"}

    req = httpx_mock.get_requests()[0]
    assert req.headers["user-agent"] == "test-mcp"
    assert req.headers["add-padding"] == "true"

    # Second call uses cache and threshold=100 -> pwned=False
    resp2 = _call_tool(
        server,
        "check_password_hash",
        {"hash_hex": digest, "threshold": 100, "pad": False},
    )
    is_err2, payload2 = _parse_tool_result(resp2)
    assert not is_err2
    assert payload2 == {"count": 42, "pwned": False, "threshold": 100, "source": "online"}
    assert len(httpx_mock.get_requests()) == 1

    # NTLM mode defaults from server when omitted
    ntlm_hash = "A" * 32
    httpx_mock.add_response(
        url="https://api.pwnedpasswords.com/range/AAAAA?mode=ntlm",
        text=f"{'A' * 27}:7\r\n",
    )
    ntlm_server = MCPServer(ntlm=True)
    resp3 = _call_tool(ntlm_server, "check_password_hash", {"hash_hex": ntlm_hash, "pad": False})
    is_err3, payload3 = _parse_tool_result(resp3)
    assert not is_err3
    assert payload3 == {"count": 7, "pwned": True, "threshold": 1, "source": "online"}
    assert "add-padding" not in httpx_mock.get_requests()[1].headers


def test_check_password_hash_offline_and_errors(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    digest_hit = _sha1_hex("letmein")
    digest_miss = _sha1_hex("unique-xyz")
    other = "0" * 40 if digest_hit != "0" * 40 else "1" * 40
    lines = sorted([f"{digest_hit}:15\n", f"{other}:2\n"])
    dump_file = tmp_path / "pwned-sha1.txt"
    dump_file.write_text("".join(lines), encoding="utf-8")

    server = MCPServer(offline_db=dump_file)
    is_err, payload = _parse_tool_result(
        _call_tool(server, "check_password_hash", {"hash_hex": digest_hit})
    )
    assert not is_err
    assert payload == {"count": 15, "pwned": True, "threshold": 1, "source": "offline"}

    is_err_miss, payload_miss = _parse_tool_result(
        _call_tool(server, "check_password_hash", {"hash_hex": digest_miss})
    )
    assert not is_err_miss
    assert payload_miss == {"count": 0, "pwned": False, "threshold": 1, "source": "offline"}

    # Validation errors -> isError=True
    for bad_args in (
        {},
        {"hash_hex": "not-valid-hex"},
        {"hash_hex": digest_hit, "threshold": 0},
        {"hash_hex": digest_hit, "threshold": True},
        {"hash_hex": digest_hit, "ntlm": "yes"},
        {"hash_hex": digest_hit, "pad": "no"},
    ):
        err, msg = _parse_tool_result(_call_tool(server, "check_password_hash", bad_args))
        assert err
        assert isinstance(msg, str) and msg

    # Missing offline db file -> OSError -> isError=True
    missing_server = MCPServer(offline_db=tmp_path / "does-not-exist.txt")
    err, msg = _parse_tool_result(
        _call_tool(missing_server, "check_password_hash", {"hash_hex": digest_hit})
    )
    assert err
    assert "does-not-exist.txt" in msg

    # HTTP error -> HIBPError -> isError=True
    httpx_mock.add_response(
        url=f"https://api.pwnedpasswords.com/range/{digest_hit[:5]}",
        status_code=500,
    )
    online_server = MCPServer()
    err, msg = _parse_tool_result(
        _call_tool(online_server, "check_password_hash", {"hash_hex": digest_hit})
    )
    assert err
    assert "HTTP 500" in msg


def test_audit_vault_bitwarden_json_online_and_offline(
    httpx_mock: HTTPXMock,
    tmp_path: Path,
) -> None:
    sample_a = "hunter2!"
    sample_b = "CorrectHorseBatteryStaple99!"
    vault_path = tmp_path / "bw.json"
    vault_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "name": "Example",
                        "login": {"username": "alice@example.com", "password": sample_a},
                    },
                    {
                        "name": "Duplicate",
                        "login": {"username": "bob@example.com", "password": sample_a},
                    },
                    {
                        "name": "Strong",
                        "login": {"username": "carol@example.com", "password": sample_b},
                    },
                ]
            }
        ),
        encoding="utf-8",
    )

    h1 = _sha1_hex(sample_a)
    h2 = _sha1_hex(sample_b)
    httpx_mock.add_response(
        url=f"https://api.pwnedpasswords.com/range/{h1[:5]}",
        text=f"{h1[5:]}:10\r\n",
    )
    httpx_mock.add_response(
        url=f"https://api.pwnedpasswords.com/range/{h2[:5]}",
        text=f"{'0' * 35}:1\r\n",
    )

    server = MCPServer()
    resp = _call_tool(server, "audit_vault", {"path": str(vault_path)})
    is_err, payload = _parse_tool_result(resp)
    assert not is_err
    assert payload["total_entries"] == 3
    assert payload["unique_passwords"] == 2
    assert payload["compromised_entries"] == 2
    assert len(payload["findings"]) == 2
    assert len(payload["reused_groups"]) == 1
    assert payload["weak_entries"] >= 2
    assert "risk_score" in payload
    dumped = json.dumps(payload)
    assert sample_a not in dumped
    assert sample_b not in dumped

    # Offline DB audit
    dump_file = tmp_path / "offline.txt"
    dump_file.write_text(f"{h1}:10\n", encoding="utf-8")
    offline_server = MCPServer(offline_db=dump_file)
    is_err2, payload2 = _parse_tool_result(
        _call_tool(
            offline_server,
            "audit_vault",
            {"path": str(vault_path), "check_reuse": False, "check_strength": False},
        )
    )
    assert not is_err2
    assert payload2["compromised_entries"] == 2
    assert "reused_groups" not in payload2
    assert "strength_findings" not in payload2


def test_audit_vault_pwdump_pass_and_rejections(
    httpx_mock: HTTPXMock,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    nt_hash = "31D6CFE0D16AE931B73C59D7E0C089C0"
    pwdump_file = tmp_path / "hashes.txt"
    pwdump_file.write_text(f"CORP\\alice:1001:aad3b435b51404eeaad3b435b51404ee:{nt_hash}:::\n")
    httpx_mock.add_response(
        url=f"https://api.pwnedpasswords.com/range/{nt_hash[:5]}?mode=ntlm",
        text=f"{nt_hash[5:]}:99\r\n",
    )

    server = MCPServer()
    is_err, payload = _parse_tool_result(
        _call_tool(server, "audit_vault", {"path": str(pwdump_file), "source": "pwdump"})
    )
    assert not is_err
    assert payload["compromised_entries"] == 1
    assert payload["findings"][0]["pwn_count"] == 99

    # pass / gopass allows omitted path
    monkeypatch.setattr(
        "pwned.mcp_server.load_export",
        lambda path, *, source, exclude_machines=False: [
            AuditEntry(name="email", username="u", password="secret")
        ],
    )
    sh = _sha1_hex("secret")
    httpx_mock.add_response(
        url=f"https://api.pwnedpasswords.com/range/{sh[:5]}",
        text=f"{sh[5:]}:5\r\n",
    )
    is_err_pass, pass_payload = _parse_tool_result(
        _call_tool(server, "audit_vault", {"source": "pass"})
    )
    assert not is_err_pass
    assert pass_payload["compromised_entries"] == 1

    # Interactive encrypted sources rejected
    for enc_source in ("keepass", "bitwarden-encrypted-json"):
        err, msg = _parse_tool_result(
            _call_tool(server, "audit_vault", {"path": str(tmp_path / "v"), "source": enc_source})
        )
        assert err
        assert "master password" in msg.lower()
        assert "mcp" in msg.lower()

    # Invalid arguments -> isError=True
    for bad_args in (
        {},  # missing path for bitwarden-json
        {"path": 123},
        {"path": str(pwdump_file), "source": 99},
    ):
        err, _ = _parse_tool_result(_call_tool(server, "audit_vault", bad_args))
        assert err


def test_audit_vault_ad_hygiene_exclude_machines_and_custom_wordlist(tmp_path: Path) -> None:
    empty_ntlm = "31D6CFE0D16AE931B73C59D7E0C089C0"
    empty_lm = "aad3b435b51404eeaad3b435b51404ee"
    present_lm = "e52cac67419a9a224a3b108f3fa6cb6d"
    pwdump_file = tmp_path / "ad.pwdump"
    pwdump_file.write_text(
        f"CORP\\blank:1001:{present_lm}:{empty_ntlm}:::\n"
        f"CORP\\DC01$:1002:{empty_lm}:{empty_ntlm}:::\n",
        encoding="utf-8",
    )
    wl_file = tmp_path / "banned.txt"
    wl_file.write_text("Acme2026!\n", encoding="utf-8")
    ntlm_db = tmp_path / "ntlm.txt"
    ntlm_db.write_text(f"{'0' * 32}:1\n", encoding="utf-8")

    server = MCPServer(offline_db=ntlm_db, ntlm=True)
    is_err, payload = _parse_tool_result(
        _call_tool(
            server,
            "audit_vault",
            {
                "path": str(pwdump_file),
                "source": "pwdump",
                "check_ad_hygiene": True,
                "exclude_machines": True,
                "custom_wordlist_path": str(wl_file),
            },
        )
    )
    assert not is_err
    assert payload["total_entries"] == 1
    assert {f["issue"] for f in payload["ad_findings"]} == {"empty_ntlm", "lm_hash_present"}
    assert payload["wordlist_matches"] == 0
    assert payload["wordlist_findings"] == []

    # Invalid custom_wordlist_path type or missing file -> isError=True
    err_type, _ = _parse_tool_result(
        _call_tool(
            server,
            "audit_vault",
            {"path": str(pwdump_file), "source": "pwdump", "custom_wordlist_path": 123},
        )
    )
    assert err_type
    err_missing, _ = _parse_tool_result(
        _call_tool(
            server,
            "audit_vault",
            {
                "path": str(pwdump_file),
                "source": "pwdump",
                "custom_wordlist_path": str(tmp_path / "missing.txt"),
            },
        )
    )
    assert err_missing


def test_audit_vault_cli_sources_allow_optional_path(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    seen_calls: list[tuple[Path | None, str, bool]] = []

    def _fake_load_export(
        path: Path | None,
        *,
        source: str,
        exclude_machines: bool = False,
    ) -> list[AuditEntry]:
        seen_calls.append((path, source, exclude_machines))
        return [AuditEntry(name="GitHub", username="alice@example.com", password="secret")]

    monkeypatch.setattr("pwned.mcp_server.load_export", _fake_load_export)

    digest = _sha1_hex("secret")
    offline_db = tmp_path / "offline.txt"
    offline_db.write_text(f"{digest}:4\n", encoding="utf-8")
    server = MCPServer(offline_db=offline_db)

    for src in ("bitwarden-cli", "1password-cli"):
        is_err, payload = _parse_tool_result(_call_tool(server, "audit_vault", {"source": src}))
        assert not is_err
        assert payload["compromised_entries"] == 1

    is_err_filtered, payload_filtered = _parse_tool_result(
        _call_tool(server, "audit_vault", {"source": "1password-cli", "path": "Work"})
    )
    assert not is_err_filtered
    assert payload_filtered["total_entries"] == 1

    assert seen_calls == [
        (None, "bitwarden-cli", False),
        (None, "1password-cli", False),
        (Path("Work"), "1password-cli", False),
    ]


def test_audit_vault_check_breaches(
    httpx_mock: HTTPXMock,
    tmp_path: Path,
) -> None:
    vault_path = tmp_path / "bw.json"
    vault_path.write_text(
        json.dumps(
            {
                "items": [
                    {
                        "name": "Adobe",
                        "login": {
                            "username": "alice@example.com",
                            "password": "UniqueStrongPassword99!",
                            "uris": [{"uri": "https://adobe.com/login"}],
                        },
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    offline_db = tmp_path / "offline.txt"
    offline_db.write_text(f"{'0' * 40}:1\n", encoding="utf-8")

    # 1. check_breaches=False does not call HIBPClient at all
    server_no_key = MCPServer(offline_db=offline_db)
    is_err_off, payload_off = _parse_tool_result(
        _call_tool(
            server_no_key,
            "audit_vault",
            {"path": str(vault_path), "check_reuse": False, "check_strength": False},
        )
    )
    assert not is_err_off
    assert "breach_findings" not in payload_off
    assert len(httpx_mock.get_requests()) == 0

    # 2. check_breaches=True without API key checks site domain catalog only
    httpx_mock.add_response(
        url="https://haveibeenpwned.com/api/v3/breaches",
        json=[SAMPLE_BREACH],
    )
    cache = ResponseCache(tmp_path / "cache", ttl_seconds=300)
    cached_server = MCPServer(offline_db=offline_db, user_agent="mcp-breach", cache=cache)
    is_err_pub, payload_pub = _parse_tool_result(
        _call_tool(
            cached_server,
            "audit_vault",
            {
                "path": str(vault_path),
                "check_reuse": False,
                "check_strength": False,
                "check_breaches": True,
            },
        )
    )
    assert not is_err_pub
    assert payload_pub["breach_correlated_entries"] == 1
    assert payload_pub["breach_findings"] == [
        {
            "name": "Adobe",
            "username": "alice@example.com",
            "source": "site_domain",
            "domain": "adobe.com",
            "breaches": ["Adobe"],
        }
    ]
    reqs = httpx_mock.get_requests()
    assert len(reqs) == 1
    assert reqs[0].headers["user-agent"] == "mcp-breach"

    # 3. check_breaches=True with API key checks both site domains and account emails
    httpx_mock.add_response(
        url="https://haveibeenpwned.com/api/v3/breachedaccount/alice%40example.com",
        json=[{"Name": "Dropbox"}],
    )
    authed_server = MCPServer(
        api_key="mcp-secret-key",
        user_agent="mcp-breach",
        offline_db=offline_db,
        cache=cache,
    )
    is_err_auth, payload_auth = _parse_tool_result(
        _call_tool(
            authed_server,
            "audit_vault",
            {
                "path": str(vault_path),
                "check_reuse": False,
                "check_strength": False,
                "check_breaches": True,
            },
        )
    )
    assert not is_err_auth
    assert payload_auth["breach_correlated_entries"] == 1
    sources = {(f["source"], tuple(f["breaches"])) for f in payload_auth["breach_findings"]}
    assert sources == {("site_domain", ("Adobe",)), ("account_breach", ("Dropbox",))}
    acct_req = httpx_mock.get_requests()[-1]
    assert acct_req.headers["hibp-api-key"] == "mcp-secret-key"

    # 4. Invalid check_breaches type -> isError=True
    err_bad, msg_bad = _parse_tool_result(
        _call_tool(
            server_no_key,
            "audit_vault",
            {"path": str(vault_path), "check_breaches": "yes"},
        )
    )
    assert err_bad
    assert "check_breaches" in msg_bad


def test_diff_baseline_all_kinds_and_errors(tmp_path: Path) -> None:
    server = MCPServer()

    # 1. breaches
    b_base = tmp_path / "b_base.json"
    b_curr = tmp_path / "b_curr.json"
    b_base.write_text(json.dumps([SAMPLE_BREACH]), encoding="utf-8")
    b_curr.write_text(json.dumps([SAMPLE_BREACH, SECOND_BREACH]), encoding="utf-8")
    err, res = _parse_tool_result(
        _call_tool(
            server,
            "diff_baseline",
            {"baseline_path": str(b_base), "current_path": str(b_curr), "kind": "breaches"},
        )
    )
    assert not err
    assert [b["Name"] for b in res] == ["Dropbox"]

    # 2. domain
    d_base = tmp_path / "d_base.json"
    d_curr = tmp_path / "d_curr.json"
    d_base.write_text(json.dumps({"alice": ["Adobe"]}), encoding="utf-8")
    d_curr.write_text(
        json.dumps({"alice": ["Adobe", "Dropbox"], "bob": ["LinkedIn"]}),
        encoding="utf-8",
    )
    err, res = _parse_tool_result(
        _call_tool(
            server,
            "diff_baseline",
            {"baseline_path": str(d_base), "current_path": str(d_curr), "kind": "domain"},
        )
    )
    assert not err
    assert res == {"alice": ["Dropbox"], "bob": ["LinkedIn"]}

    # 3. search
    s_base = tmp_path / "s_base.json"
    s_curr = tmp_path / "s_curr.json"
    s_base.write_text(
        json.dumps({"breaches": [SAMPLE_BREACH], "pastes": [], "stealer_logs": ["a.com"]}),
        encoding="utf-8",
    )
    s_curr.write_text(
        json.dumps(
            {
                "breaches": [SAMPLE_BREACH, SECOND_BREACH],
                "pastes": [{"Source": "Pastebin", "Id": "p1", "EmailCount": 3}],
                "stealer_logs": ["a.com", "b.com"],
            }
        ),
        encoding="utf-8",
    )
    err, res = _parse_tool_result(
        _call_tool(
            server,
            "diff_baseline",
            {"baseline_path": str(s_base), "current_path": str(s_curr), "kind": "search"},
        )
    )
    assert not err
    assert [b["Name"] for b in res["breaches"]] == ["Dropbox"]
    assert len(res["pastes"]) == 1
    assert res["stealer_logs"] == ["b.com"]

    # 4. account_batch
    a_base = tmp_path / "a_base.json"
    a_curr = tmp_path / "a_curr.json"
    a_base.write_text(
        json.dumps([{"account": "a@b.com", "breaches": ["Adobe"], "status": "pwned"}]),
        encoding="utf-8",
    )
    a_curr.write_text(
        json.dumps(
            [
                {"account": "a@b.com", "breaches": ["Adobe", "Dropbox"], "status": "pwned"},
                {"account": "c@d.com", "breaches": [], "status": "clean"},
            ]
        ),
        encoding="utf-8",
    )
    err, res = _parse_tool_result(
        _call_tool(
            server,
            "diff_baseline",
            {"baseline_path": str(a_base), "current_path": str(a_curr), "kind": "account_batch"},
        )
    )
    assert not err
    assert res[0]["breaches"] == ["Dropbox"]
    assert res[1]["status"] == "clean"

    # Errors: invalid kind, malformed current (ValidationError), missing file (OSError)
    err_kind, _ = _parse_tool_result(
        _call_tool(
            server,
            "diff_baseline",
            {"baseline_path": str(b_base), "current_path": str(b_curr), "kind": "other"},
        )
    )
    assert err_kind

    bad_curr = tmp_path / "bad_curr.json"
    bad_curr.write_text(json.dumps([{"not": "a breach"}]), encoding="utf-8")
    err_val, _ = _parse_tool_result(
        _call_tool(
            server,
            "diff_baseline",
            {"baseline_path": str(b_base), "current_path": str(bad_curr), "kind": "breaches"},
        )
    )
    assert err_val

    err_missing, _ = _parse_tool_result(
        _call_tool(
            server,
            "diff_baseline",
            {
                "baseline_path": str(tmp_path / "nope.json"),
                "current_path": str(b_curr),
                "kind": "breaches",
            },
        )
    )
    assert err_missing


def test_lookup_breach_single_list_and_errors(httpx_mock: HTTPXMock, tmp_path: Path) -> None:
    httpx_mock.add_response(
        url="https://haveibeenpwned.com/api/v3/breach/Adobe",
        json=SAMPLE_BREACH,
    )
    httpx_mock.add_response(
        url="https://haveibeenpwned.com/api/v3/breaches?domain=adobe.com&includeUnverified=false",
        json=[SAMPLE_BREACH],
    )
    httpx_mock.add_response(
        url="https://haveibeenpwned.com/api/v3/breach/Missing",
        status_code=404,
    )

    cache = ResponseCache(tmp_path / "cache", ttl_seconds=300)
    server = MCPServer(cache=cache)

    err, res = _parse_tool_result(_call_tool(server, "lookup_breach", {"name": "Adobe"}))
    assert not err
    assert res["Name"] == "Adobe"

    err2, res2 = _parse_tool_result(
        _call_tool(
            server,
            "lookup_breach",
            {"domain": "adobe.com", "include_unverified": False},
        )
    )
    assert not err2
    assert len(res2) == 1
    assert res2[0]["Domain"] == "adobe.com"

    # Cached list call hits cache without extra HTTP request
    err3, res3 = _parse_tool_result(
        _call_tool(
            server,
            "lookup_breach",
            {"domain": "adobe.com", "include_unverified": False},
        )
    )
    assert not err3
    assert res3 == res2
    assert len(httpx_mock.get_requests()) == 2

    # 404 -> HIBPError -> isError=True
    err4, msg4 = _parse_tool_result(_call_tool(server, "lookup_breach", {"name": "Missing"}))
    assert err4
    assert "Not found" in msg4

    # Non-string name -> isError=True
    err5, _ = _parse_tool_result(_call_tool(server, "lookup_breach", {"name": 42}))
    assert err5


def test_check_account_range(httpx_mock: HTTPXMock) -> None:
    no_key_server = MCPServer()
    err, msg = _parse_tool_result(
        _call_tool(no_key_server, "check_account_range", {"email": "alice@example.com"})
    )
    assert err
    assert msg == "HIBP API key is required for check_account_range."

    email = "alice@example.com"
    digest = _sha1_hex(email)
    prefix, suffix = digest[:6], digest[6:]
    httpx_mock.add_response(
        url=f"https://haveibeenpwned.com/api/v3/breachedaccount/range/{prefix}",
        json=[{"hashSuffix": suffix, "websites": ["Adobe", "Dropbox"]}],
    )

    server = MCPServer(api_key="test-key-123", user_agent="mcp-agent")
    err1, res1 = _parse_tool_result(_call_tool(server, "check_account_range", {"email": email}))
    assert not err1
    assert res1 == {"email": email, "breaches": ["Adobe", "Dropbox"], "pwned": True}
    req = httpx_mock.get_requests()[0]
    assert req.headers["hibp-api-key"] == "test-key-123"
    assert req.headers["user-agent"] == "mcp-agent"

    # Clean email (404 -> [])
    clean_email = "clean@example.com"
    clean_prefix = _sha1_hex(clean_email)[:6]
    httpx_mock.add_response(
        url=f"https://haveibeenpwned.com/api/v3/breachedaccount/range/{clean_prefix}",
        status_code=404,
    )
    err2, res2 = _parse_tool_result(
        _call_tool(server, "check_account_range", {"email": clean_email})
    )
    assert not err2
    assert res2 == {"email": clean_email, "breaches": [], "pwned": False}

    # Missing email -> isError=True
    err3, _ = _parse_tool_result(_call_tool(server, "check_account_range", {}))
    assert err3


def test_serve_stdio_streams_and_default_stdio(monkeypatch: pytest.MonkeyPatch) -> None:
    server = MCPServer()
    lines = [
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize"}),
        "",
        "   ",
        json.dumps({"jsonrpc": "2.0", "method": "notifications/initialized"}),
        "{not-json",
        json.dumps({"jsonrpc": "2.0", "id": 2, "method": "ping"}),
    ]
    in_buf = io.StringIO("\n".join(lines) + "\n")
    out_buf = io.StringIO()

    serve_stdio(server, in_stream=in_buf, out_stream=out_buf)

    responses = [json.loads(line) for line in out_buf.getvalue().splitlines()]
    assert len(responses) == 3
    assert responses[0]["id"] == 1
    assert responses[0]["result"]["protocolVersion"] == MCP_PROTOCOL_VERSION
    assert responses[1]["error"]["code"] == -32700
    assert responses[2] == {"jsonrpc": "2.0", "id": 2, "result": {}}

    # Default stdin / stdout fallback
    default_in = io.StringIO(json.dumps({"jsonrpc": "2.0", "id": 5, "method": "ping"}) + "\n")
    default_out = io.StringIO()
    monkeypatch.setattr(sys, "stdin", default_in)
    monkeypatch.setattr(sys, "stdout", default_out)
    serve_stdio(server)
    assert json.loads(default_out.getvalue().strip()) == {
        "jsonrpc": "2.0",
        "id": 5,
        "result": {},
    }
