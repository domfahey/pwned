from __future__ import annotations

import json
import sys
from collections.abc import Callable
from pathlib import Path
from typing import Any, TextIO, cast

from pydantic import TypeAdapter, ValidationError

from pwned.audit import ExportSource, audit_entries, load_custom_wordlist, load_export
from pwned.baseline import (
    diff_account_batch,
    diff_breaches,
    diff_domain_breaches,
    diff_search_result,
    load_baseline,
)
from pwned.batch import AccountBatchItem
from pwned.cache import ResponseCache
from pwned.client import HIBPClient, HIBPError
from pwned.config import DEFAULT_USER_AGENT
from pwned.formatting import serialize
from pwned.models import Breach, SearchResult
from pwned.offline import OfflinePasswordsClient
from pwned.passwords import PwnedPasswordsClient

MCP_PROTOCOL_VERSION = "2024-11-05"
JSONRPC_VERSION = "2.0"

_REJECTED_MCP_SOURCES = frozenset({"keepass", "bitwarden-encrypted-json"})
_STORE_SOURCES = frozenset({"pass", "gopass", "bitwarden-cli", "1password-cli"})

_breaches_adapter: TypeAdapter[list[Breach]] = TypeAdapter(list[Breach])
_domain_breaches_adapter: TypeAdapter[dict[str, list[str]]] = TypeAdapter(dict[str, list[str]])
_account_batch_adapter: TypeAdapter[list[AccountBatchItem]] = TypeAdapter(list[AccountBatchItem])

_TOOL_DEFINITIONS: tuple[dict[str, Any], ...] = (
    {
        "name": "check_password_hash",
        "description": (
            "Check a precomputed SHA-1 (40-char) or NTLM (32-char) password hash "
            "against Pwned Passwords via k-anonymity or a local offline dump. "
            "Never accepts or logs plaintext passwords."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "hash_hex": {
                    "type": "string",
                    "description": "Full 40-char SHA-1 or 32-char NTLM hexadecimal hash.",
                },
                "ntlm": {
                    "type": "boolean",
                    "description": "Treat hash_hex as NTLM instead of SHA-1.",
                },
                "pad": {
                    "type": "boolean",
                    "default": True,
                    "description": "Send Add-Padding header for online range queries.",
                },
                "threshold": {
                    "type": "integer",
                    "minimum": 1,
                    "default": 1,
                    "description": "Minimum breach count required to mark as pwned.",
                },
            },
            "required": ["hash_hex"],
            "additionalProperties": False,
        },
    },
    {
        "name": "audit_vault",
        "description": (
            "Audit a plaintext password-manager export or local pass/gopass store for "
            "compromised, reused, and weak passwords. Returns sanitized findings only; "
            "encrypted vaults requiring master passwords are rejected."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "path": {
                    "type": "string",
                    "description": (
                        "Path to export file (optional for pass, gopass, bitwarden-cli, "
                        "and 1password-cli)."
                    ),
                },
                "source": {
                    "type": "string",
                    "default": "bitwarden-json",
                    "description": (
                        "Vault export format (e.g. bitwarden-json, csv, pwdump, pass, "
                        "bitwarden-cli, 1password-cli)."
                    ),
                },
                "threshold": {
                    "type": "integer",
                    "minimum": 1,
                    "default": 1,
                    "description": "Minimum breach count to report as compromised.",
                },
                "ntlm": {
                    "type": "boolean",
                    "default": False,
                    "description": "Check NTLM hashes (automatically enabled for pwdump).",
                },
                "check_reuse": {
                    "type": "boolean",
                    "default": True,
                    "description": "Detect reused passwords across entries.",
                },
                "check_strength": {
                    "type": "boolean",
                    "default": True,
                    "description": "Evaluate local password strength and risk score.",
                },
                "check_ad_hygiene": {
                    "type": "boolean",
                    "default": False,
                    "description": (
                        "Check AD hygiene (empty NTLM hashes, legacy LM hashes, "
                        "and username-as-password)."
                    ),
                },
                "exclude_machines": {
                    "type": "boolean",
                    "default": False,
                    "description": "Exclude Active Directory computer accounts ending with '$'.",
                },
                "custom_wordlist_path": {
                    "type": "string",
                    "description": "Optional path to a custom newline-delimited banned wordlist.",
                },
                "check_breaches": {
                    "type": "boolean",
                    "default": False,
                    "description": (
                        "Correlate vault entry domains (and account emails when API key "
                        "is configured) against HIBP breaches."
                    ),
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "diff_baseline",
        "description": (
            "Diff a current JSON snapshot against a saved baseline JSON snapshot "
            "for breaches, domain breaches, account search results, or account batches."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "baseline_path": {
                    "type": "string",
                    "description": "Path to the previous baseline JSON file.",
                },
                "current_path": {
                    "type": "string",
                    "description": "Path to the current snapshot JSON file.",
                },
                "kind": {
                    "type": "string",
                    "enum": ["breaches", "domain", "search", "account_batch"],
                    "description": "Baseline data kind to diff.",
                },
            },
            "required": ["baseline_path", "current_path", "kind"],
            "additionalProperties": False,
        },
    },
    {
        "name": "lookup_breach",
        "description": (
            "Look up a single HIBP breach by name or list breaches optionally filtered by domain."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "name": {
                    "type": "string",
                    "description": "Breach name to look up; lists breaches when omitted.",
                },
                "domain": {
                    "type": "string",
                    "description": "Optional domain filter when listing breaches.",
                },
                "include_unverified": {
                    "type": "boolean",
                    "default": True,
                    "description": "Include unverified breaches when listing breaches.",
                },
            },
            "additionalProperties": False,
        },
    },
    {
        "name": "check_account_range",
        "description": (
            "Check an email address for breaches using HIBP 6-char SHA-1 k-anonymity "
            "account range search. Requires an HIBP API key."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "email": {
                    "type": "string",
                    "description": "Email address to check via k-anonymity range.",
                },
            },
            "required": ["email"],
            "additionalProperties": False,
        },
    },
)


def _server_version() -> str:
    from pwned import __version__

    return __version__


def _error_response(req_id: Any, code: int, message: str) -> dict[str, Any]:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": req_id,
        "error": {"code": code, "message": message},
    }


def _result_response(req_id: Any, result: Any) -> dict[str, Any]:
    return {
        "jsonrpc": JSONRPC_VERSION,
        "id": req_id,
        "result": result,
    }


def _require_str(args: dict[str, Any], key: str) -> str:
    value = args.get(key)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"'{key}' must be a non-empty string.")
    return value


def _optional_str(args: dict[str, Any], key: str) -> str | None:
    value = args.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ValueError(f"'{key}' must be a string.")
    return value


def _get_bool(args: dict[str, Any], key: str, default: bool) -> bool:
    value = args.get(key)
    if value is None:
        return default
    if not isinstance(value, bool):
        raise ValueError(f"'{key}' must be a boolean.")
    return value


def _get_positive_int(args: dict[str, Any], key: str, default: int) -> int:
    value = args.get(key)
    if value is None:
        return default
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"'{key}' must be an integer >= 1.")
    return value


class MCPServer:
    """Zero-dependency, privacy-first local JSON-RPC 2.0 MCP server for pwned."""

    def __init__(
        self,
        *,
        api_key: str | None = None,
        user_agent: str = DEFAULT_USER_AGENT,
        offline_db: Path | None = None,
        ntlm: bool = False,
        cache: ResponseCache | None = None,
    ) -> None:
        self._api_key = api_key
        self._user_agent = user_agent
        self._offline_db = offline_db
        self._ntlm = ntlm
        self._cache = cache
        self._tool_handlers: dict[str, Callable[[dict[str, Any]], Any]] = {
            "check_password_hash": self._tool_check_password_hash,
            "audit_vault": self._tool_audit_vault,
            "diff_baseline": self._tool_diff_baseline,
            "lookup_breach": self._tool_lookup_breach,
            "check_account_range": self._tool_check_account_range,
        }

    def list_tools(self) -> list[dict[str, Any]]:
        """Return MCP tool definitions exposed by this server."""
        return list(_TOOL_DEFINITIONS)

    def _open_password_client(
        self,
        *,
        ntlm: bool,
    ) -> OfflinePasswordsClient | PwnedPasswordsClient:
        if self._offline_db is not None:
            return OfflinePasswordsClient(self._offline_db, ntlm=ntlm)
        return PwnedPasswordsClient(user_agent=self._user_agent, cache=self._cache)

    def _tool_check_password_hash(self, arguments: dict[str, Any]) -> dict[str, Any]:
        hash_hex = _require_str(arguments, "hash_hex")
        use_ntlm = _get_bool(arguments, "ntlm", self._ntlm)
        pad = _get_bool(arguments, "pad", True)
        threshold = _get_positive_int(arguments, "threshold", 1)

        with self._open_password_client(ntlm=use_ntlm) as client:
            count = client.check_hash(hash_hex, ntlm=use_ntlm, pad=pad)

        return {
            "count": count,
            "pwned": count >= threshold,
            "threshold": threshold,
            "source": "offline" if self._offline_db is not None else "online",
        }

    def _tool_audit_vault(self, arguments: dict[str, Any]) -> Any:
        raw_source = arguments.get("source")
        source = "bitwarden-json" if raw_source is None else raw_source
        if not isinstance(source, str) or not source.strip():
            raise ValueError("'source' must be a non-empty string.")
        if source in _REJECTED_MCP_SOURCES:
            raise ValueError(
                f"Source {source!r} is not supported over MCP because master passwords "
                "must not be sent through an MCP chat prompt."
            )

        raw_path = _optional_str(arguments, "path")
        if raw_path is None or not raw_path.strip():
            if source not in _STORE_SOURCES:
                raise ValueError(f"'path' is required for source {source!r}.")
            resolved_path: Path | None = None
        else:
            resolved_path = Path(raw_path)

        threshold = _get_positive_int(arguments, "threshold", 1)
        use_ntlm = _get_bool(arguments, "ntlm", self._ntlm) or (source == "pwdump")
        check_reuse = _get_bool(arguments, "check_reuse", True)
        check_strength = _get_bool(arguments, "check_strength", True)
        check_ad_hygiene = _get_bool(arguments, "check_ad_hygiene", False)
        exclude_machines = _get_bool(arguments, "exclude_machines", False)
        check_breaches = _get_bool(arguments, "check_breaches", False)
        raw_wordlist = _optional_str(arguments, "custom_wordlist_path")
        wordlist_terms = (
            load_custom_wordlist(Path(raw_wordlist))
            if raw_wordlist is not None and raw_wordlist.strip()
            else None
        )

        entries = load_export(
            resolved_path,
            source=cast(ExportSource, source),
            exclude_machines=exclude_machines,
        )
        with self._open_password_client(ntlm=use_ntlm) as client:
            if check_breaches:
                with HIBPClient(
                    api_key=self._api_key,
                    user_agent=self._user_agent,
                    cache=self._cache,
                ) as hibp_client:
                    summary = audit_entries(
                        entries,
                        client,
                        threshold=threshold,
                        ntlm=use_ntlm,
                        check_reuse=check_reuse,
                        check_strength=check_strength,
                        check_ad_hygiene=check_ad_hygiene,
                        custom_wordlist=wordlist_terms,
                        check_breaches=True,
                        hibp_client=hibp_client,
                    )
            else:
                summary = audit_entries(
                    entries,
                    client,
                    threshold=threshold,
                    ntlm=use_ntlm,
                    check_reuse=check_reuse,
                    check_strength=check_strength,
                    check_ad_hygiene=check_ad_hygiene,
                    custom_wordlist=wordlist_terms,
                )
        return serialize(summary)

    def _tool_diff_baseline(self, arguments: dict[str, Any]) -> Any:
        baseline_path = Path(_require_str(arguments, "baseline_path"))
        current_path = Path(_require_str(arguments, "current_path"))
        kind = _require_str(arguments, "kind")
        if kind not in ("breaches", "domain", "search", "account_batch"):
            raise ValueError(f"Unsupported baseline kind: {kind!r}.")

        previous = load_baseline(baseline_path)
        current_raw = load_baseline(current_path)

        diffed: Any
        if kind == "breaches":
            diffed = diff_breaches(_breaches_adapter.validate_python(current_raw), previous)
        elif kind == "domain":
            diffed = diff_domain_breaches(
                _domain_breaches_adapter.validate_python(current_raw),
                previous,
            )
        elif kind == "search":
            diffed = diff_search_result(SearchResult.model_validate(current_raw), previous)
        else:
            diffed = diff_account_batch(
                _account_batch_adapter.validate_python(current_raw),
                previous,
            )
        return serialize(diffed)

    def _tool_lookup_breach(self, arguments: dict[str, Any]) -> Any:
        name = _optional_str(arguments, "name")
        domain = _optional_str(arguments, "domain")
        include_unverified = _get_bool(arguments, "include_unverified", True)

        with HIBPClient(user_agent=self._user_agent, cache=self._cache) as client:
            if name:
                return serialize(client.get_breach(name))
            return serialize(
                client.get_breaches(domain=domain, include_unverified=include_unverified)
            )

    def _tool_check_account_range(self, arguments: dict[str, Any]) -> dict[str, Any]:
        email = _require_str(arguments, "email")
        if not self._api_key:
            raise ValueError("HIBP API key is required for check_account_range.")

        with HIBPClient(api_key=self._api_key, user_agent=self._user_agent) as client:
            breaches = client.check_account_range(email)

        return {
            "email": email,
            "breaches": breaches,
            "pwned": bool(breaches),
        }

    def _handle_tools_call(self, req_id: Any, message: dict[str, Any]) -> dict[str, Any]:
        params = message.get("params")
        if not isinstance(params, dict):
            return _error_response(req_id, -32602, "Invalid params")

        name = params.get("name")
        raw_arguments = params.get("arguments")
        arguments = {} if raw_arguments is None else raw_arguments
        if not isinstance(name, str) or not isinstance(arguments, dict):
            return _error_response(req_id, -32602, "Invalid params")

        handler = self._tool_handlers.get(name)
        if handler is None:
            return _error_response(req_id, -32602, f"Unknown tool: {name}")

        try:
            tool_result = handler(arguments)
        except (ValueError, OSError, RuntimeError, HIBPError, ValidationError) as exc:
            return _result_response(
                req_id,
                {"content": [{"type": "text", "text": str(exc)}], "isError": True},
            )

        return _result_response(
            req_id,
            {
                "content": [{"type": "text", "text": json.dumps(tool_result, indent=2)}],
                "isError": False,
            },
        )

    def handle_message(self, message: Any) -> dict[str, Any] | None:
        """Process a single decoded JSON-RPC 2.0 message and return a response or None."""
        if not isinstance(message, dict) or message.get("jsonrpc") != JSONRPC_VERSION:
            req_id = message.get("id") if isinstance(message, dict) else None
            return _error_response(req_id, -32600, "Invalid Request")

        method = message.get("method")
        if not isinstance(method, str):
            return _error_response(message.get("id"), -32600, "Invalid Request")

        if method == "notifications/initialized" or (
            method.startswith("notifications/") and "id" not in message
        ):
            return None

        req_id = message.get("id")
        if method == "initialize":
            return _result_response(
                req_id,
                {
                    "protocolVersion": MCP_PROTOCOL_VERSION,
                    "capabilities": {"tools": {}},
                    "serverInfo": {"name": "pwned", "version": _server_version()},
                },
            )
        if method == "ping":
            return _result_response(req_id, {})
        if method == "tools/list":
            return _result_response(req_id, {"tools": self.list_tools()})
        if method == "tools/call":
            return self._handle_tools_call(req_id, message)

        if "id" not in message:
            return None
        return _error_response(req_id, -32601, "Method not found")


def serve_stdio(
    server: MCPServer,
    *,
    in_stream: TextIO | None = None,
    out_stream: TextIO | None = None,
) -> None:
    """Serve JSON-RPC 2.0 MCP requests line-by-line over stdio streams."""
    reader = sys.stdin if in_stream is None else in_stream
    writer = sys.stdout if out_stream is None else out_stream

    for raw_line in reader:
        line = raw_line.strip()
        if not line:
            continue
        try:
            message = json.loads(line)
        except json.JSONDecodeError as exc:
            response: dict[str, Any] | None = _error_response(None, -32700, f"Parse error: {exc}")
        else:
            response = server.handle_message(message)

        if response is not None:
            writer.write(json.dumps(response) + "\n")
            writer.flush()
