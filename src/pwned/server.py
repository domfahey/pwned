from __future__ import annotations

import hashlib
import os
import threading
import time
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import BinaryIO, Literal, Protocol, cast
from urllib.parse import parse_qs, urlsplit

import httpx

from pwned._parsers import _parse_range_response
from pwned.cache import ResponseCache
from pwned.client import REQUEST_TIMEOUT, HIBPError
from pwned.config import DEFAULT_USER_AGENT
from pwned.models import _HIBPBase
from pwned.offline import OfflinePasswordsClient, _find_line_start
from pwned.passwords import PwnedPasswordsClient, _validate_prefix

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8080
DEFAULT_CACHE_CONTROL = "public, max-age=3600"

_SHA1_SUFFIX_LEN = 35
_NTLM_SUFFIX_LEN = 27
_PADDING_MIN_LINES = 800
_PADDING_BUCKET_SPAN = 201  # 800..1000 inclusive

ServerBackendKind = Literal["offline", "proxy"]
ServerModeKind = Literal["sha1", "ntlm", "auto"]


class ServerHealth(_HIBPBase):
    """Health check payload returned by ``GET /healthz``."""

    status: Literal["ok"] = "ok"
    backend: ServerBackendKind
    mode: ServerModeKind
    uptime_seconds: float


class ServerMetrics:
    """Thread-safe counters and Prometheus exposition renderer for ``PwnedRangeServer``."""

    def __init__(self, *, started_at: float | None = None) -> None:
        self._lock = threading.Lock()
        self._started_at = time.monotonic() if started_at is None else started_at
        self._range_requests_total = 0
        self._range_padded_responses_total = 0
        self._range_errors_total = 0
        self._range_upstream_errors_total = 0

    @property
    def uptime_seconds(self) -> float:
        """Return server uptime in seconds since initialization."""
        return max(0.0, time.monotonic() - self._started_at)

    def record_request(self) -> None:
        """Increment total ``/range`` requests counter."""
        with self._lock:
            self._range_requests_total += 1

    def record_padded_response(self) -> None:
        """Increment total padded ``/range`` responses counter."""
        with self._lock:
            self._range_padded_responses_total += 1

    def record_error(self, *, upstream: bool = False) -> None:
        """Increment ``/range`` error counters."""
        with self._lock:
            self._range_errors_total += 1
            if upstream:
                self._range_upstream_errors_total += 1

    def snapshot(self) -> dict[str, int | float]:
        """Return a consistent point-in-time dictionary snapshot of all metrics."""
        with self._lock:
            return {
                "pwned_range_requests_total": self._range_requests_total,
                "pwned_range_padded_responses_total": self._range_padded_responses_total,
                "pwned_range_errors_total": self._range_errors_total,
                "pwned_range_upstream_errors_total": self._range_upstream_errors_total,
                "pwned_server_uptime_seconds": round(self.uptime_seconds, 6),
            }

    def render_prometheus(self) -> str:
        """Render metrics in Prometheus text exposition format (0.0.4)."""
        snap = self.snapshot()
        lines = [
            "# HELP pwned_range_requests_total Total number of /range requests received.",
            "# TYPE pwned_range_requests_total counter",
            f"pwned_range_requests_total {snap['pwned_range_requests_total']}",
            "# HELP pwned_range_padded_responses_total Total number of padded /range responses.",
            "# TYPE pwned_range_padded_responses_total counter",
            f"pwned_range_padded_responses_total {snap['pwned_range_padded_responses_total']}",
            "# HELP pwned_range_errors_total Total number of /range request errors.",
            "# TYPE pwned_range_errors_total counter",
            f"pwned_range_errors_total {snap['pwned_range_errors_total']}",
            "# HELP pwned_range_upstream_errors_total Total number of upstream HIBP proxy errors.",
            "# TYPE pwned_range_upstream_errors_total counter",
            f"pwned_range_upstream_errors_total {snap['pwned_range_upstream_errors_total']}",
            "# HELP pwned_server_uptime_seconds Server uptime in seconds.",
            "# TYPE pwned_server_uptime_seconds gauge",
            f"pwned_server_uptime_seconds {snap['pwned_server_uptime_seconds']}",
        ]
        return "\n".join(lines) + "\n"


def _check_offline_mode(*, configured_ntlm: bool, requested_ntlm: bool) -> None:
    if requested_ntlm != configured_ntlm:
        expected = "ntlm" if configured_ntlm else "sha1"
        requested = "ntlm" if requested_ntlm else "sha1"
        raise ValueError(
            f"Offline server is configured for {expected} mode; got mode={requested!r}"
        )


def _read_file_range(file_handle: BinaryIO, prefix: str) -> dict[str, int]:
    """Binary-search a sorted single-file HIBP dump and return all suffixes matching ``prefix``."""
    target = prefix.encode("ascii")
    file_size = os.fstat(file_handle.fileno()).st_size
    low = 0
    high = file_size

    while low < high:
        mid = (low + high) // 2
        line_start = _find_line_start(file_handle, mid)
        file_handle.seek(line_start)
        raw_line = file_handle.readline()
        line_end = file_handle.tell()
        line_prefix = raw_line.strip()[:5].upper()
        if line_prefix < target:
            low = line_end
        else:
            high = line_start

    file_handle.seek(low)
    matching_lines: list[str] = []
    while True:
        raw_line = file_handle.readline()
        if not raw_line:
            break
        line_text = raw_line.decode("utf-8", errors="ignore").strip()
        if line_text[:5].upper() != prefix:
            break
        matching_lines.append(line_text[5:])

    return _parse_range_response("\n".join(matching_lines))


def _pad_range(prefix: str, entries: dict[str, int], *, ntlm: bool) -> dict[str, int]:
    """Deterministically pad a range dict with zero-count suffixes to 800-1000 lines."""
    suffix_len = _NTLM_SUFFIX_LEN if ntlm else _SHA1_SUFFIX_LEN
    target_lines = _PADDING_MIN_LINES + (int(prefix, 16) % _PADDING_BUCKET_SPAN)
    padded = dict(entries)
    counter = 0
    while len(padded) < target_lines:
        candidate = (
            hashlib.sha256(f"{prefix}:{counter}".encode("ascii")).hexdigest()[:suffix_len].upper()
        )
        counter += 1
        padded.setdefault(candidate, 0)
    return padded


def _format_range_body(entries: dict[str, int]) -> bytes:
    """Format suffix -> count mapping as sorted HIBP CRLF range response bytes."""
    if not entries:
        return b""
    return "".join(f"{suffix}:{count}\r\n" for suffix, count in sorted(entries.items())).encode(
        "utf-8"
    )


def _parse_mode_query(query: str) -> bool:
    """Parse optional ``?mode=sha1|ntlm`` query parameter into a boolean NTLM flag."""
    params = parse_qs(query, keep_blank_values=True)
    mode_values = params.get("mode")
    if not mode_values:
        return False
    mode = mode_values[-1].strip().lower()
    if mode == "sha1":
        return False
    if mode == "ntlm":
        return True
    raise ValueError("Invalid mode parameter; expected 'sha1' or 'ntlm'")


class _RangeBackend(Protocol):
    backend_name: ServerBackendKind
    mode_name: ServerModeKind

    def get_range(self, prefix: str, *, ntlm: bool) -> dict[str, int]: ...
    def close(self) -> None: ...


class _OfflineDirectoryBackend:
    backend_name: ServerBackendKind = "offline"

    def __init__(self, directory: Path, *, ntlm: bool) -> None:
        self._directory = directory
        self._ntlm = ntlm
        self.mode_name: ServerModeKind = "ntlm" if ntlm else "sha1"

    def get_range(self, prefix: str, *, ntlm: bool) -> dict[str, int]:
        _check_offline_mode(configured_ntlm=self._ntlm, requested_ntlm=ntlm)
        prefix_file = self._directory / f"{prefix}.txt"
        if not prefix_file.is_file():
            return {}
        return _parse_range_response(prefix_file.read_text(encoding="utf-8"))

    def close(self) -> None:
        return


class _OfflineFileBackend:
    backend_name: ServerBackendKind = "offline"

    def __init__(self, file_path: Path, *, ntlm: bool) -> None:
        self._ntlm = ntlm
        self.mode_name: ServerModeKind = "ntlm" if ntlm else "sha1"
        self._file: BinaryIO = file_path.open("rb")
        self._lock = threading.Lock()

    def get_range(self, prefix: str, *, ntlm: bool) -> dict[str, int]:
        _check_offline_mode(configured_ntlm=self._ntlm, requested_ntlm=ntlm)
        with self._lock:
            return _read_file_range(self._file, prefix)

    def close(self) -> None:
        self._file.close()


class _UpstreamProxyBackend:
    backend_name: ServerBackendKind = "proxy"
    mode_name: ServerModeKind = "auto"

    def __init__(
        self,
        *,
        user_agent: str,
        timeout: float,
        cache: ResponseCache | None,
        proxy: str | None,
        upstream_pad: bool,
        http_client: httpx.Client | None,
    ) -> None:
        self._client = PwnedPasswordsClient(
            user_agent=user_agent,
            timeout=timeout,
            proxy=proxy,
            client=http_client,
            cache=cache,
        )
        self._upstream_pad = upstream_pad

    def get_range(self, prefix: str, *, ntlm: bool) -> dict[str, int]:
        return self._client.get_password_range(
            prefix,
            ntlm=ntlm,
            pad=self._upstream_pad,
        )

    def close(self) -> None:
        self._client.close()


class _RangeRequestHandler(BaseHTTPRequestHandler):
    server_version = "pwned-range-server"
    sys_version = ""

    @property
    def _range_server(self) -> PwnedRangeServer:
        return cast(_RangeThreadingHTTPServer, self.server).range_server

    def log_message(self, format: str, *args: object) -> None:
        if self._range_server.access_log:
            super().log_message(format, *args)

    def _send_response(
        self,
        status: HTTPStatus,
        body: bytes,
        *,
        content_type: str = "text/plain; charset=utf-8",
        extra_headers: dict[str, str] | None = None,
        send_body: bool = True,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        if extra_headers:
            for key, value in extra_headers.items():
                self.send_header(key, value)
        self.end_headers()
        if send_body and body:
            self.wfile.write(body)

    def _handle_healthz(self) -> None:
        payload = self._range_server.health().model_dump_json().encode("utf-8")
        self._send_response(
            HTTPStatus.OK,
            payload,
            content_type="application/json",
        )

    def _handle_metrics(self) -> None:
        range_server = self._range_server
        if not range_server.enable_metrics:
            self._send_response(HTTPStatus.NOT_FOUND, b"Not Found\n")
            return
        body = range_server.metrics.render_prometheus().encode("utf-8")
        self._send_response(
            HTTPStatus.OK,
            body,
            content_type="text/plain; version=0.0.4; charset=utf-8",
        )

    def _handle_range(self, raw_prefix: str, query: str) -> None:
        range_server = self._range_server
        range_server.metrics.record_request()
        try:
            prefix = _validate_prefix(raw_prefix)
            req_ntlm = _parse_mode_query(query)
            entries = range_server.lookup_range(prefix, ntlm=req_ntlm)
        except ValueError as exc:
            range_server.metrics.record_error()
            self._send_response(HTTPStatus.BAD_REQUEST, f"{exc}\n".encode())
            return
        except HIBPError:
            range_server.metrics.record_error(upstream=True)
            self._send_response(
                HTTPStatus.BAD_GATEWAY,
                b"Bad Gateway: upstream HIBP range request failed\n",
            )
            return

        pad = self.headers.get("Add-Padding", "").strip().lower() == "true"
        headers: dict[str, str] = {"Cache-Control": DEFAULT_CACHE_CONTROL}
        if pad:
            entries = _pad_range(prefix, entries, ntlm=req_ntlm)
            headers["Add-Padding"] = "true"
            range_server.metrics.record_padded_response()

        body = _format_range_body(entries)
        self._send_response(HTTPStatus.OK, body, extra_headers=headers)

    def _handle_method_not_allowed(self) -> None:
        self._send_response(
            HTTPStatus.METHOD_NOT_ALLOWED,
            b"Method Not Allowed\n",
            extra_headers={"Allow": "GET"},
            send_body=self.command != "HEAD",
        )

    def do_GET(self) -> None:  # noqa: N802
        parsed = urlsplit(self.path)
        path = parsed.path
        if path == "/healthz":
            self._handle_healthz()
            return
        if path == "/metrics":
            self._handle_metrics()
            return
        if path.startswith("/range/"):
            raw_prefix = path.removeprefix("/range/")
            if raw_prefix and "/" not in raw_prefix:
                self._handle_range(raw_prefix, parsed.query)
                return
        self._send_response(HTTPStatus.NOT_FOUND, b"Not Found\n")

    do_POST = _handle_method_not_allowed  # noqa: N815
    do_PUT = _handle_method_not_allowed  # noqa: N815
    do_DELETE = _handle_method_not_allowed  # noqa: N815
    do_PATCH = _handle_method_not_allowed  # noqa: N815
    do_OPTIONS = _handle_method_not_allowed  # noqa: N815
    do_HEAD = _handle_method_not_allowed  # noqa: N815


class _RangeThreadingHTTPServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(
        self,
        server_address: tuple[str, int],
        range_server: PwnedRangeServer,
    ) -> None:
        self.range_server = range_server
        super().__init__(server_address, _RangeRequestHandler)


class PwnedRangeServer:
    """Self-hosted HIBP k-anonymity range HTTP server and caching proxy.

    Serves ``GET /range/<prefix>`` compatible with ``api.pwnedpasswords.com`` from either:
    - An offline HIBP dump (single sorted file or per-prefix range directory), or
    - An upstream caching proxy backed by ``PwnedPasswordsClient``.
    """

    def __init__(
        self,
        *,
        host: str = DEFAULT_HOST,
        port: int = DEFAULT_PORT,
        offline_db: str | os.PathLike[str] | None = None,
        ntlm: bool = False,
        user_agent: str = DEFAULT_USER_AGENT,
        timeout: float = REQUEST_TIMEOUT,
        cache: ResponseCache | None = None,
        proxy: str | None = None,
        upstream_pad: bool = True,
        http_client: httpx.Client | None = None,
        enable_metrics: bool = True,
        access_log: bool = False,
    ) -> None:
        self._enable_metrics = enable_metrics
        self._access_log = access_log
        self._metrics = ServerMetrics()

        offline_path: Path | None = None
        is_offline_dir = False
        if offline_db is not None:
            offline_path = Path(offline_db)
            with OfflinePasswordsClient(offline_path, ntlm=ntlm) as validated:
                is_offline_dir = validated.is_directory

        self._httpd = _RangeThreadingHTTPServer((host, port), self)

        self._backend: _RangeBackend
        if offline_path is not None:
            if is_offline_dir:
                self._backend = _OfflineDirectoryBackend(offline_path, ntlm=ntlm)
            else:
                self._backend = _OfflineFileBackend(offline_path, ntlm=ntlm)
        else:
            self._backend = _UpstreamProxyBackend(
                user_agent=user_agent,
                timeout=timeout,
                cache=cache,
                proxy=proxy,
                upstream_pad=upstream_pad,
                http_client=http_client,
            )

    @property
    def server_address(self) -> tuple[str, int]:
        """Return the bound ``(host, port)`` tuple."""
        addr = self._httpd.server_address
        return str(addr[0]), int(addr[1])

    @property
    def url(self) -> str:
        """Return the base HTTP URL for this server."""
        host, port = self.server_address
        return f"http://{host}:{port}"

    @property
    def metrics(self) -> ServerMetrics:
        """Return the server's thread-safe metrics collector."""
        return self._metrics

    @property
    def backend(self) -> ServerBackendKind:
        """Return ``'offline'`` or ``'proxy'``."""
        return self._backend.backend_name

    @property
    def mode(self) -> ServerModeKind:
        """Return ``'sha1'``, ``'ntlm'``, or ``'auto'``."""
        return self._backend.mode_name

    @property
    def enable_metrics(self) -> bool:
        """Return whether ``GET /metrics`` is enabled."""
        return self._enable_metrics

    @property
    def access_log(self) -> bool:
        """Return whether HTTP request access logging to stderr is enabled."""
        return self._access_log

    def health(self) -> ServerHealth:
        """Return the current health snapshot model."""
        return ServerHealth(
            backend=self.backend,
            mode=self.mode,
            uptime_seconds=round(self._metrics.uptime_seconds, 6),
        )

    def lookup_range(self, prefix: str, *, ntlm: bool = False) -> dict[str, int]:
        """Return compromised hash suffixes and counts for a 5-char hex prefix."""
        normalized_prefix = _validate_prefix(prefix)
        return self._backend.get_range(normalized_prefix, ntlm=ntlm)

    def serve_forever(self, poll_interval: float = 0.5) -> None:
        """Start serving HTTP requests until ``shutdown()`` is called."""
        self._httpd.serve_forever(poll_interval=poll_interval)

    def shutdown(self) -> None:
        """Stop the ``serve_forever()`` loop."""
        self._httpd.shutdown()

    def close(self) -> None:
        """Close the listening socket and any underlying backend resources."""
        self._httpd.server_close()
        self._backend.close()

    def __enter__(self) -> PwnedRangeServer:
        return self

    def __exit__(self, *args: object) -> None:
        self.close()


def create_range_server(
    *,
    host: str = DEFAULT_HOST,
    port: int = DEFAULT_PORT,
    offline_db: str | os.PathLike[str] | None = None,
    ntlm: bool = False,
    user_agent: str = DEFAULT_USER_AGENT,
    timeout: float = REQUEST_TIMEOUT,
    cache: ResponseCache | None = None,
    proxy: str | None = None,
    upstream_pad: bool = True,
    http_client: httpx.Client | None = None,
    enable_metrics: bool = True,
    access_log: bool = False,
) -> PwnedRangeServer:
    """Create and return a configured ``PwnedRangeServer`` instance."""
    return PwnedRangeServer(
        host=host,
        port=port,
        offline_db=offline_db,
        ntlm=ntlm,
        user_agent=user_agent,
        timeout=timeout,
        cache=cache,
        proxy=proxy,
        upstream_pad=upstream_pad,
        http_client=http_client,
        enable_metrics=enable_metrics,
        access_log=access_log,
    )
