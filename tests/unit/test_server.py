from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import Any

import httpx
import pytest

from pwned._parsers import _parse_range_response
from pwned.cache import ResponseCache
from pwned.offline_index import build_bloom_filter, build_compact_index
from pwned.passwords import PwnedPasswordsClient, _hash_password
from pwned.server import (
    DEFAULT_CACHE_CONTROL,
    DEFAULT_HOST,
    DEFAULT_PORT,
    PwnedRangeServer,
    ServerHealth,
    ServerMetrics,
    create_range_server,
)


def _sha1_hex(value: str) -> str:
    return _hash_password(value, ntlm=False)


def _ntlm_hex(value: str) -> str:
    return _hash_password(value, ntlm=True)


def _write_dump(
    path: Path,
    entries: list[tuple[str, int]],
    *,
    newline: str = "\n",
    trailing_newline: bool = True,
) -> Path:
    sorted_entries = sorted(entries, key=lambda item: item[0].upper())
    body = newline.join(f"{digest}:{count}" for digest, count in sorted_entries)
    if trailing_newline and body:
        body += newline
    path.write_bytes(body.encode("ascii"))
    return path


def _write_range_dir(
    directory: Path,
    entries: list[tuple[str, int]],
    *,
    newline: str = "\n",
    index_mode: str | None = None,
) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    grouped: dict[str, list[tuple[str, int]]] = {}
    for digest, count in entries:
        prefix = digest[:5].upper()
        suffix = digest[5:].upper()
        grouped.setdefault(prefix, []).append((suffix, count))
    for prefix, items in grouped.items():
        items.sort(key=lambda item: item[0])
        body = newline.join(f"{suffix}:{count}" for suffix, count in items) + newline
        (directory / f"{prefix}.txt").write_text(body, encoding="utf-8")
    if index_mode is not None:
        (directory / ".pwned-index.json").write_text(
            json.dumps({"mode": index_mode}),
            encoding="utf-8",
        )
    return directory


@contextmanager
def _running_server(server: PwnedRangeServer) -> Iterator[PwnedRangeServer]:
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.02},
        daemon=True,
    )
    thread.start()
    try:
        yield server
    finally:
        server.shutdown()
        thread.join(timeout=5.0)
        server.close()


class TestServerMetrics:
    def test_initial_snapshot_and_prometheus_output(self) -> None:
        metrics = ServerMetrics()
        snap = metrics.snapshot()
        assert snap["pwned_range_requests_total"] == 0
        assert snap["pwned_range_padded_responses_total"] == 0
        assert snap["pwned_range_errors_total"] == 0
        assert snap["pwned_range_upstream_errors_total"] == 0
        assert isinstance(snap["pwned_server_uptime_seconds"], float)
        assert snap["pwned_server_uptime_seconds"] >= 0.0

        prom = metrics.render_prometheus()
        assert "# TYPE pwned_range_requests_total counter\n" in prom
        assert "pwned_range_requests_total 0\n" in prom
        assert "# TYPE pwned_range_padded_responses_total counter\n" in prom
        assert "pwned_range_padded_responses_total 0\n" in prom
        assert "# TYPE pwned_range_errors_total counter\n" in prom
        assert "pwned_range_errors_total 0\n" in prom
        assert "# TYPE pwned_range_upstream_errors_total counter\n" in prom
        assert "pwned_range_upstream_errors_total 0\n" in prom
        assert "# TYPE pwned_server_uptime_seconds gauge\n" in prom

    def test_counters_and_thread_safety(self) -> None:
        metrics = ServerMetrics()

        def worker() -> None:
            for _ in range(25):
                metrics.record_request()
                metrics.record_padded_response()
                metrics.record_error()
                metrics.record_error(upstream=True)

        threads = [threading.Thread(target=worker) for _ in range(4)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        snap = metrics.snapshot()
        assert snap["pwned_range_requests_total"] == 100
        assert snap["pwned_range_padded_responses_total"] == 100
        assert snap["pwned_range_errors_total"] == 200
        assert snap["pwned_range_upstream_errors_total"] == 100

    def test_custom_started_at_clamps_negative_uptime(self) -> None:
        metrics = ServerMetrics(started_at=1e18)
        assert metrics.uptime_seconds == 0.0


class TestOfflineSingleFileMode:
    def test_sha1_single_file_large_same_prefix_cluster(self, tmp_path: Path) -> None:
        # Ensure lower-bound binary search rewinds to the very first line of a large cluster
        entries: list[tuple[str, int]] = []
        for i in range(15):
            entries.append((f"5BAA5{i:035X}", i + 1))
        for i in range(50):
            entries.append((f"5BAA6{i:035X}", i + 100))
        for i in range(15):
            entries.append((f"5BAA7{i:035X}", i + 1))
        dump = _write_dump(tmp_path / "cluster.txt", entries)

        server = create_range_server(host="127.0.0.1", port=0, offline_db=str(dump))
        with _running_server(server), httpx.Client(base_url=server.url) as client:
            resp = client.get("/range/5BAA6")
            assert resp.status_code == 200
            parsed = _parse_range_response(resp.text)
            assert len(parsed) == 50
            assert parsed[f"{0:035X}"] == 100
            assert parsed[f"{49:035X}"] == 149

    def test_sha1_single_file_hits_misses_and_formatting(self, tmp_path: Path) -> None:
        pw_hash = _sha1_hex("password")  # 5BAA6...
        prefix = pw_hash[:5]
        suffix_a = "0" * 35
        suffix_b = pw_hash[5:]
        suffix_z = "F" * 35
        dump = _write_dump(
            tmp_path / "sha1.txt",
            [
                ("00001" + "A" * 35, 3),
                (f"{prefix}{suffix_z}", 9),
                (f"{prefix}{suffix_a}", 1),
                (f"{prefix}{suffix_b}", 3861493),
                ("FFFFE" + "B" * 35, 7),
            ],
            newline="\r\n",
            trailing_newline=False,
        )

        server = create_range_server(host="127.0.0.1", port=0, offline_db=dump)
        with _running_server(server), httpx.Client(base_url=server.url) as client:
            # Hit with lowercase prefix and default mode (sha1)
            resp = client.get(f"/range/{prefix.lower()}")
            assert resp.status_code == 200
            assert resp.headers["content-type"] == "text/plain; charset=utf-8"
            assert resp.headers["cache-control"] == DEFAULT_CACHE_CONTROL
            assert "add-padding" not in resp.headers
            expected_lines = sorted(
                [
                    f"{suffix_a}:1",
                    f"{suffix_b}:3861493",
                    f"{suffix_z}:9",
                ]
            )
            assert resp.text == "".join(f"{line}\r\n" for line in expected_lines)

            # Explicit ?mode=sha1 and uppercase ?mode=SHA1
            resp_sha1 = client.get(f"/range/{prefix}", params={"mode": "SHA1"})
            assert resp_sha1.status_code == 200
            assert _parse_range_response(resp_sha1.text)[suffix_b] == 3861493

            # Hit on very first entry and very last entry (EOF break path)
            resp_first = client.get("/range/00001")
            assert resp_first.status_code == 200
            assert resp_first.text == f"{'A' * 35}:3\r\n"

            resp_last = client.get("/range/FFFFE")
            assert resp_last.status_code == 200
            assert resp_last.text == f"{'B' * 35}:7\r\n"

            # Misses: before first, between entries, after last
            for missing_prefix in ("00000", "5BAA7", "FFFFF"):
                miss = client.get(f"/range/{missing_prefix}")
                assert miss.status_code == 200
                assert miss.text == ""

            # Mode mismatch (?mode=ntlm on SHA-1 offline server) -> 400
            mismatch = client.get(f"/range/{prefix}", params={"mode": "ntlm"})
            assert mismatch.status_code == 400
            assert "sha1" in mismatch.text.lower()

    def test_empty_single_file_and_malformed_zero_entries(self, tmp_path: Path) -> None:
        empty_dump = tmp_path / "empty.txt"
        empty_dump.write_bytes(b"")

        server = create_range_server(host="127.0.0.1", port=0, offline_db=empty_dump)
        with _running_server(server), httpx.Client(base_url=server.url) as client:
            resp = client.get("/range/5BAA6")
            assert resp.status_code == 200
            assert resp.text == ""

        mixed_dump = tmp_path / "mixed.txt"
        mixed_dump.write_text(
            "\n".join(
                [
                    "5baa6" + "1" * 35 + ":0",
                    "5baa6" + "2" * 35 + ":notanint",
                    "5baa6MALFORMED_NO_COLON",
                    "5baa6" + "3" * 35 + ":17",
                ]
            )
            + "\n",
            encoding="utf-8",
        )
        server2 = create_range_server(host="127.0.0.1", port=0, offline_db=mixed_dump)
        with _running_server(server2), httpx.Client(base_url=server2.url) as client:
            resp = client.get("/range/5BAA6")
            assert resp.status_code == 200
            assert resp.text == f"{'3' * 35}:17\r\n"

    def test_ntlm_single_file_and_mode_rejection(self, tmp_path: Path) -> None:
        ntlm_hash = _ntlm_hex("password")
        prefix = ntlm_hash[:5]
        suffix = ntlm_hash[5:]
        assert len(suffix) == 27
        dump = _write_dump(tmp_path / "ntlm.txt", [(ntlm_hash, 555)])

        server = create_range_server(host="127.0.0.1", port=0, offline_db=dump, ntlm=True)
        with _running_server(server), httpx.Client(base_url=server.url) as client:
            ok = client.get(f"/range/{prefix}", params={"mode": "ntlm"})
            assert ok.status_code == 200
            assert ok.text == f"{suffix}:555\r\n"

            # Omitted mode defaults to sha1 -> rejected on ntlm offline server
            bad_default = client.get(f"/range/{prefix}")
            assert bad_default.status_code == 400
            assert "ntlm" in bad_default.text.lower()

            bad_sha1 = client.get(f"/range/{prefix}", params={"mode": "sha1"})
            assert bad_sha1.status_code == 400

    def test_missing_offline_file_fails_fast(self, tmp_path: Path) -> None:
        with pytest.raises(FileNotFoundError):
            create_range_server(host="127.0.0.1", port=0, offline_db=tmp_path / "missing.txt")

    def test_concurrent_single_file_lookups_are_thread_safe(self, tmp_path: Path) -> None:
        entries = [(f"{i:05X}" + f"{i:035X}", i + 1) for i in range(1, 50)]
        dump = _write_dump(tmp_path / "concurrent.txt", entries)

        server = create_range_server(host="127.0.0.1", port=0, offline_db=dump)
        errors: list[str] = []

        with _running_server(server):

            def query(idx: int) -> None:
                prefix = f"{idx:05X}"
                expected_suffix = f"{idx:035X}"
                with httpx.Client(base_url=server.url) as client:
                    resp = client.get(f"/range/{prefix}")
                    if resp.status_code != 200 or resp.text != f"{expected_suffix}:{idx + 1}\r\n":
                        errors.append(f"Mismatch for {prefix}: {resp.status_code} {resp.text!r}")

            threads = [threading.Thread(target=query, args=(i,)) for i in range(1, 30)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()

        assert errors == []


class TestOfflineDirectoryMode:
    def test_sha1_directory_existing_missing_and_malformed(self, tmp_path: Path) -> None:
        pw_hash = _sha1_hex("password")
        prefix = pw_hash[:5]
        suffix = pw_hash[5:]
        dump_dir = _write_range_dir(
            tmp_path / "sha1_dir",
            [(pw_hash, 1234)],
            index_mode="sha1",
        )
        # Inject malformed and zero-count lines into prefix file
        prefix_file = dump_dir / f"{prefix}.txt"
        prefix_file.write_text(
            f"{suffix}:1234\nBADLINE\n{'0' * 35}:0\n{'1' * 35}:abc\n",
            encoding="utf-8",
        )

        server = create_range_server(host="127.0.0.1", port=0, offline_db=dump_dir)
        with _running_server(server), httpx.Client(base_url=server.url) as client:
            hit = client.get(f"/range/{prefix}")
            assert hit.status_code == 200
            assert hit.text == f"{suffix}:1234\r\n"

            miss = client.get("/range/00000")
            assert miss.status_code == 200
            assert miss.text == ""

            mismatch = client.get(f"/range/{prefix}", params={"mode": "ntlm"})
            assert mismatch.status_code == 400

    def test_ntlm_directory_and_startup_mode_mismatch(self, tmp_path: Path) -> None:
        ntlm_hash = _ntlm_hex("hunter2")
        prefix = ntlm_hash[:5]
        suffix = ntlm_hash[5:]
        dump_dir = _write_range_dir(
            tmp_path / "ntlm_dir",
            [(ntlm_hash, 88)],
            index_mode="ntlm",
        )

        # Opening NTLM directory with ntlm=False fails fast with ValueError
        with pytest.raises(ValueError, match="NTLM"):
            create_range_server(host="127.0.0.1", port=0, offline_db=dump_dir, ntlm=False)

        server = create_range_server(host="127.0.0.1", port=0, offline_db=dump_dir, ntlm=True)
        with _running_server(server), httpx.Client(base_url=server.url) as client:
            ok = client.get(f"/range/{prefix}", params={"mode": "ntlm"})
            assert ok.status_code == 200
            assert ok.text == f"{suffix}:88\r\n"

            bad = client.get(f"/range/{prefix}")
            assert bad.status_code == 400


class TestOfflineCompactAndBloomMode:
    def test_compact_sha1_direct_lookup_and_lifecycle(self, tmp_path: Path) -> None:
        pw_hash = _sha1_hex("password")
        prefix = pw_hash[:5]
        suffix = pw_hash[5:]
        other_suffix = "A" * 35
        src = _write_dump(
            tmp_path / "sha1.txt",
            [
                (pw_hash, 3861493),
                (f"{prefix}{other_suffix}", 7),
                ("FFFFE" + "B" * 35, 3),
            ],
        )
        compact_path = tmp_path / "sha1.pwnb"
        build_compact_index(src, compact_path)

        with create_range_server(host="127.0.0.1", port=0, offline_db=compact_path) as server:
            assert server.backend == "offline"
            assert server.mode == "sha1"
            assert server.lookup_range(prefix) == {
                other_suffix: 7,
                suffix: 3861493,
            }
            assert server.lookup_range("00000") == {}
            assert server.lookup_range("FFFFE") == {"B" * 35: 3}
            with pytest.raises(ValueError, match="sha1"):
                server.lookup_range(prefix, ntlm=True)

        # Idempotent close after context exit
        server.close()

    def test_compact_ntlm_direct_lookup_and_startup_mode_mismatch(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        ntlm_hash = _ntlm_hex("hunter2")
        prefix = ntlm_hash[:5]
        suffix = ntlm_hash[5:]
        src = _write_dump(tmp_path / "ntlm.txt", [(ntlm_hash, 88)])
        compact_ntlm = tmp_path / "ntlm.pwnb"
        build_compact_index(src, compact_ntlm, ntlm=True)

        # Opening NTLM compact index in SHA-1 mode fails before binding a socket
        with monkeypatch.context() as mp:

            def fail_http_server(*args: Any, **kwargs: Any) -> Any:
                raise AssertionError("HTTP server socket should not be bound on invalid mode")

            mp.setattr("pwned.server._RangeThreadingHTTPServer", fail_http_server)
            with pytest.raises(ValueError, match="NTLM"):
                create_range_server(host="127.0.0.1", port=0, offline_db=compact_ntlm, ntlm=False)

        with create_range_server(
            host="127.0.0.1", port=0, offline_db=compact_ntlm, ntlm=True
        ) as server:
            assert server.backend == "offline"
            assert server.mode == "ntlm"
            assert server.lookup_range(prefix, ntlm=True) == {suffix: 88}
            assert server.lookup_range("00000", ntlm=True) == {}
            with pytest.raises(ValueError, match="ntlm"):
                server.lookup_range(prefix, ntlm=False)

    def test_bloom_filter_rejected_before_binding_socket(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        sha1_src = _write_dump(tmp_path / "sha1.txt", [(_sha1_hex("password"), 10)])
        bloom_sha1 = tmp_path / "sha1.pwnl"
        build_bloom_filter(sha1_src, bloom_sha1)

        ntlm_src = _write_dump(tmp_path / "ntlm.txt", [(_ntlm_hex("password"), 10)])
        bloom_ntlm = tmp_path / "ntlm.pwnl"
        build_bloom_filter(ntlm_src, bloom_ntlm, ntlm=True)

        def fail_http_server(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("HTTP server socket must not be bound for Bloom filters")

        monkeypatch.setattr("pwned.server._RangeThreadingHTTPServer", fail_http_server)

        with pytest.raises(ValueError, match="Bloom filters cannot serve"):
            create_range_server(host="127.0.0.1", port=0, offline_db=bloom_sha1)

        with pytest.raises(ValueError, match="Bloom filters cannot serve"):
            create_range_server(host="127.0.0.1", port=0, offline_db=bloom_ntlm, ntlm=True)

    def test_compact_sha1_http_hit_miss_mismatch_and_padding(self, tmp_path: Path) -> None:
        pw_hash = _sha1_hex("password")
        prefix = pw_hash[:5]
        suffix = pw_hash[5:]
        other_suffix = "0" * 35
        expected_padded_lines = 800 + (int(prefix, 16) % 201)
        src = _write_dump(
            tmp_path / "sha1.txt",
            [
                (f"{prefix}{other_suffix}", 4),
                (pw_hash, 12345),
            ],
        )
        compact_path = tmp_path / "sha1.pwnb"
        build_compact_index(src, compact_path)

        server = create_range_server(host="127.0.0.1", port=0, offline_db=compact_path)
        with _running_server(server), httpx.Client(base_url=server.url) as client:
            health = client.get("/healthz")
            assert health.status_code == 200
            assert health.json()["backend"] == "offline"
            assert health.json()["mode"] == "sha1"

            hit = client.get(f"/range/{prefix.lower()}")
            assert hit.status_code == 200
            expected_lines = sorted([f"{other_suffix}:4", f"{suffix}:12345"])
            assert hit.text == "".join(f"{line}\r\n" for line in expected_lines)

            miss = client.get("/range/00000")
            assert miss.status_code == 200
            assert miss.text == ""

            mismatch = client.get(f"/range/{prefix}", params={"mode": "ntlm"})
            assert mismatch.status_code == 400
            assert "sha1" in mismatch.text.lower()

            padded = client.get(f"/range/{prefix}", headers={"Add-Padding": "true"})
            assert padded.status_code == 200
            assert padded.headers["add-padding"] == "true"
            entries = padded.text.split("\r\n")[:-1]
            assert len(entries) == expected_padded_lines
            parsed = {line.split(":")[0]: int(line.split(":")[1]) for line in entries}
            assert parsed[suffix] == 12345
            assert parsed[other_suffix] == 4
            assert all(len(s) == 35 for s in parsed)

    def test_compact_ntlm_http_hit_miss_mismatch_and_padding(self, tmp_path: Path) -> None:
        ntlm_hash = _ntlm_hex("password")
        prefix = ntlm_hash[:5]
        suffix = ntlm_hash[5:]
        expected_padded_lines = 800 + (int(prefix, 16) % 201)
        src = _write_dump(tmp_path / "ntlm.txt", [(ntlm_hash, 555)])
        compact_ntlm = tmp_path / "ntlm.pwnb"
        build_compact_index(src, compact_ntlm, ntlm=True)

        server = create_range_server(host="127.0.0.1", port=0, offline_db=compact_ntlm, ntlm=True)
        with _running_server(server), httpx.Client(base_url=server.url) as client:
            health = client.get("/healthz")
            assert health.status_code == 200
            assert health.json()["backend"] == "offline"
            assert health.json()["mode"] == "ntlm"

            hit = client.get(f"/range/{prefix}", params={"mode": "ntlm"})
            assert hit.status_code == 200
            assert hit.text == f"{suffix}:555\r\n"

            miss = client.get("/range/00000", params={"mode": "ntlm"})
            assert miss.status_code == 200
            assert miss.text == ""

            bad_default = client.get(f"/range/{prefix}")
            assert bad_default.status_code == 400
            assert "ntlm" in bad_default.text.lower()

            padded = client.get(
                f"/range/{prefix}",
                params={"mode": "ntlm"},
                headers={"Add-Padding": "true"},
            )
            assert padded.status_code == 200
            assert padded.headers["add-padding"] == "true"
            entries = padded.text.split("\r\n")[:-1]
            assert len(entries) == expected_padded_lines
            parsed = {line.split(":")[0]: int(line.split(":")[1]) for line in entries}
            assert parsed[suffix] == 555
            assert all(len(s) == 27 for s in parsed)


class TestUpstreamProxyMode:
    def test_proxy_sha1_ntlm_caching_and_upstream_pad(self, tmp_path: Path) -> None:
        sha1_hash = _sha1_hex("password")
        ntlm_hash = _ntlm_hex("password")
        seen_requests: list[tuple[str, str | None, str | None]] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_requests.append(
                (
                    request.url.path,
                    request.url.params.get("mode"),
                    request.headers.get("Add-Padding"),
                )
            )
            if request.url.params.get("mode") == "ntlm":
                return httpx.Response(200, text=f"{ntlm_hash[5:]}:99\r\n{'0' * 27}:0\r\n")
            return httpx.Response(200, text=f"{sha1_hash[5:]}:3861493\r\n{'0' * 35}:0\r\n")

        upstream_client = httpx.Client(
            base_url="https://api.pwnedpasswords.com",
            transport=httpx.MockTransport(handler),
        )
        cache = ResponseCache(tmp_path / "cache", ttl_seconds=60)
        server = create_range_server(
            host="127.0.0.1",
            port=0,
            cache=cache,
            http_client=upstream_client,
            upstream_pad=True,
        )
        try:
            with _running_server(server), httpx.Client(base_url=server.url) as client:
                r1 = client.get(f"/range/{sha1_hash[:5]}")
                assert r1.status_code == 200
                assert r1.text == f"{sha1_hash[5:]}:3861493\r\n"

                # Second call for same SHA-1 prefix hits cache (no new upstream call)
                r2 = client.get(f"/range/{sha1_hash[:5]}")
                assert r2.status_code == 200
                assert r2.text == r1.text

                # Dynamic ?mode=ntlm hits upstream with mode=ntlm
                r3 = client.get(f"/range/{ntlm_hash[:5]}", params={"mode": "ntlm"})
                assert r3.status_code == 200
                assert r3.text == f"{ntlm_hash[5:]}:99\r\n"

                assert seen_requests == [
                    (f"/range/{sha1_hash[:5]}", None, "true"),
                    (f"/range/{ntlm_hash[:5]}", "ntlm", "true"),
                ]
        finally:
            assert not upstream_client.is_closed
            upstream_client.close()

    def test_proxy_upstream_pad_false_omits_header(self) -> None:
        seen_headers: list[str | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen_headers.append(request.headers.get("Add-Padding"))
            return httpx.Response(200, text=f"{'A' * 35}:5\r\n")

        upstream_client = httpx.Client(
            base_url="https://api.pwnedpasswords.com",
            transport=httpx.MockTransport(handler),
        )
        server = create_range_server(
            host="127.0.0.1",
            port=0,
            http_client=upstream_client,
            upstream_pad=False,
        )
        try:
            with _running_server(server), httpx.Client(base_url=server.url) as client:
                resp = client.get("/range/5BAA6")
                assert resp.status_code == 200
                assert resp.text == f"{'A' * 35}:5\r\n"
                assert seen_headers == [None]
        finally:
            assert not upstream_client.is_closed
            upstream_client.close()

    def test_proxy_upstream_error_returns_502_and_increments_metrics(self) -> None:
        def failing_handler(request: httpx.Request) -> httpx.Response:
            if request.url.path.endswith("AAAAA"):
                return httpx.Response(503, text="Upstream secret stack trace")
            raise httpx.ConnectError("connection refused", request=request)

        upstream_client = httpx.Client(
            base_url="https://api.pwnedpasswords.com",
            transport=httpx.MockTransport(failing_handler),
        )
        server = create_range_server(
            host="127.0.0.1",
            port=0,
            http_client=upstream_client,
            upstream_pad=False,
        )
        try:
            with _running_server(server), httpx.Client(base_url=server.url) as client:
                r1 = client.get("/range/AAAAA")
                assert r1.status_code == 502
                assert "secret stack trace" not in r1.text

                r2 = client.get("/range/BBBBB")
                assert r2.status_code == 502
                assert "connection refused" not in r2.text

                snap = server.metrics.snapshot()
                assert snap["pwned_range_requests_total"] == 2
                assert snap["pwned_range_errors_total"] == 2
                assert snap["pwned_range_upstream_errors_total"] == 2
        finally:
            upstream_client.close()

    def test_end_to_end_with_pwned_passwords_client(self, tmp_path: Path) -> None:
        sha1_hash = _sha1_hex("password")
        dump = _write_dump(tmp_path / "sha1.txt", [(sha1_hash, 4242)])
        server = create_range_server(host="127.0.0.1", port=0, offline_db=dump)

        with (
            _running_server(server),
            httpx.Client(base_url=server.url) as http_client,
            PwnedPasswordsClient(client=http_client) as pw_client,
        ):
            assert pw_client.check_password("password", pad=True) == 4242
            assert pw_client.check_password("password", pad=False) == 4242
            assert pw_client.check_password("not-in-dump-xyz", pad=True) == 0


class TestPadding:
    def test_padding_sha1_deterministic_sorted_and_preserves_counts(self, tmp_path: Path) -> None:
        pw_hash = _sha1_hex("password")
        prefix = pw_hash[:5]
        real_suffix = pw_hash[5:]
        expected_lines = 800 + (int(prefix, 16) % 201)
        dump = _write_dump(tmp_path / "sha1.txt", [(pw_hash, 9001)])

        server = create_range_server(host="127.0.0.1", port=0, offline_db=dump)
        with _running_server(server), httpx.Client(base_url=server.url) as client:
            r1 = client.get(f"/range/{prefix}", headers={"add-padding": "TRUE"})
            r2 = client.get(f"/range/{prefix.lower()}", headers={"Add-Padding": "true"})

            assert r1.status_code == 200
            assert r1.headers["add-padding"] == "true"
            assert r1.headers["server"] == "pwned-range-server"
            assert r1.text == r2.text

            raw_lines = r1.text.split("\r\n")
            assert raw_lines[-1] == ""
            entries = raw_lines[:-1]
            assert len(entries) == expected_lines
            assert 800 <= len(entries) <= 1000

            suffixes: list[str] = []
            counts: dict[str, int] = {}
            for line in entries:
                suffix, count_str = line.split(":")
                assert len(suffix) == 35
                suffixes.append(suffix)
                counts[suffix] = int(count_str)

            assert suffixes == sorted(suffixes)
            assert len(set(suffixes)) == len(suffixes)
            assert counts[real_suffix] == 9001
            assert sum(1 for c in counts.values() if c == 0) == expected_lines - 1

            # Add-Padding: false does not pad
            unpadded = client.get(f"/range/{prefix}", headers={"Add-Padding": "false"})
            assert unpadded.status_code == 200
            assert "add-padding" not in unpadded.headers
            assert unpadded.text == f"{real_suffix}:9001\r\n"

            # Padding on empty prefix miss still returns deterministic fake lines
            empty_padded = client.get("/range/00000", headers={"Add-Padding": "true"})
            assert empty_padded.status_code == 200
            assert empty_padded.headers["add-padding"] == "true"
            empty_entries = empty_padded.text.split("\r\n")[:-1]
            assert len(empty_entries) == 800
            assert all(
                line.endswith(":0") and len(line.split(":")[0]) == 35 for line in empty_entries
            )

    def test_padding_ntlm_uses_27_char_suffixes(self, tmp_path: Path) -> None:
        ntlm_hash = _ntlm_hex("password")
        prefix = ntlm_hash[:5]
        real_suffix = ntlm_hash[5:]
        expected_lines = 800 + (int(prefix, 16) % 201)
        dump = _write_dump(tmp_path / "ntlm.txt", [(ntlm_hash, 77)])

        server = create_range_server(host="127.0.0.1", port=0, offline_db=dump, ntlm=True)
        with _running_server(server), httpx.Client(base_url=server.url) as client:
            resp = client.get(
                f"/range/{prefix}",
                params={"mode": "ntlm"},
                headers={"Add-Padding": "true"},
            )
            assert resp.status_code == 200
            assert resp.headers["add-padding"] == "true"
            entries = resp.text.split("\r\n")[:-1]
            assert len(entries) == expected_lines
            suffixes = [line.split(":")[0] for line in entries]
            assert suffixes == sorted(suffixes)
            assert all(len(s) == 27 for s in suffixes)
            parsed = dict(line.split(":") for line in entries)
            assert parsed[real_suffix] == "77"
            assert sum(1 for v in parsed.values() if v == "0") == expected_lines - 1

    def test_padding_collision_avoidance_and_already_large_bucket(self, tmp_path: Path) -> None:
        prefix = "00000"  # target_lines == 800
        # Precompute exact first deterministic fake suffix candidate
        colliding_suffix = hashlib.sha256(f"{prefix}:0".encode("ascii")).hexdigest()[:35].upper()
        dump = _write_dump(tmp_path / "collision.txt", [(f"{prefix}{colliding_suffix}", 42)])

        server = create_range_server(host="127.0.0.1", port=0, offline_db=dump)
        with _running_server(server), httpx.Client(base_url=server.url) as client:
            resp = client.get(f"/range/{prefix}", headers={"Add-Padding": "true"})
            assert resp.status_code == 200
            entries = resp.text.split("\r\n")[:-1]
            assert len(entries) == 800
            parsed = {line.split(":")[0]: int(line.split(":")[1]) for line in entries}
            assert parsed[colliding_suffix] == 42

        # Prefix with >= target_lines real entries (805 entries > 800 target)
        large_entries = [(f"{prefix}{i:035X}", i + 1) for i in range(805)]
        large_dump = _write_dump(tmp_path / "large.txt", large_entries)
        large_server = create_range_server(host="127.0.0.1", port=0, offline_db=large_dump)
        with _running_server(large_server), httpx.Client(base_url=large_server.url) as client:
            resp = client.get(f"/range/{prefix}", headers={"Add-Padding": "true"})
            assert resp.status_code == 200
            assert resp.headers["add-padding"] == "true"
            entries = resp.text.split("\r\n")[:-1]
            assert len(entries) == 805


class TestValidationAndErrors:
    def test_invalid_prefix_invalid_mode_404_and_405(self, tmp_path: Path) -> None:
        dump = _write_dump(tmp_path / "sha1.txt", [(_sha1_hex("password"), 10)])
        server = create_range_server(host="127.0.0.1", port=0, offline_db=dump)

        with _running_server(server), httpx.Client(base_url=server.url) as client:
            # Invalid prefixes -> 400 (never padded even when Add-Padding: true is sent)
            for bad_prefix in ("123", "ZZZZZ", "123456"):
                resp = client.get(f"/range/{bad_prefix}", headers={"Add-Padding": "true"})
                assert resp.status_code == 400
                assert "add-padding" not in resp.headers
            assert server.metrics.snapshot()["pwned_range_padded_responses_total"] == 0

            # Invalid ?mode= -> 400
            for query in ("?mode=md5", "?mode="):
                resp = client.get(f"/range/5BAA6{query}")
                assert resp.status_code == 400

            # Unknown / non-exact routes -> 404
            for bad_path in (
                "/",
                "/unknown",
                "/range",
                "/range/",
                "/range/5BAA6/",
                "/range/5BAA6/extra",
                "/healthz/extra",
            ):
                resp = client.get(bad_path)
                assert resp.status_code == 404

            # Non-GET methods -> 405 with Allow: GET
            for method in ("POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"):
                resp = client.request(method, "/range/5BAA6")
                assert resp.status_code == 405
                assert resp.headers["allow"] == "GET"


class TestHealthAndMetrics:
    def test_healthz_offline_sha1_offline_ntlm_and_proxy(self, tmp_path: Path) -> None:
        sha1_dump = _write_dump(tmp_path / "sha1.txt", [])
        ntlm_dump = _write_dump(tmp_path / "ntlm.txt", [])

        cases = [
            (
                create_range_server(host="127.0.0.1", port=0, offline_db=sha1_dump),
                "offline",
                "sha1",
            ),
            (
                create_range_server(host="127.0.0.1", port=0, offline_db=ntlm_dump, ntlm=True),
                "offline",
                "ntlm",
            ),
            (create_range_server(host="127.0.0.1", port=0), "proxy", "auto"),
        ]
        for server, expected_backend, expected_mode in cases:
            with _running_server(server), httpx.Client(base_url=server.url) as client:
                resp = client.get("/healthz")
                assert resp.status_code == 200
                assert resp.headers["content-type"] == "application/json"
                data = resp.json()
                assert data["status"] == "ok"
                assert data["backend"] == expected_backend
                assert data["mode"] == expected_mode
                assert isinstance(data["uptime_seconds"], float)
                assert data["uptime_seconds"] >= 0.0

                health = server.health()
                assert isinstance(health, ServerHealth)
                assert health.backend == expected_backend
                assert health.mode == expected_mode

    def test_metrics_enabled_and_disabled(self, tmp_path: Path) -> None:
        pw_hash = _sha1_hex("password")
        dump = _write_dump(tmp_path / "sha1.txt", [(pw_hash, 5)])

        server = create_range_server(
            host="127.0.0.1",
            port=0,
            offline_db=dump,
            enable_metrics=True,
        )
        with _running_server(server), httpx.Client(base_url=server.url) as client:
            assert server.enable_metrics is True
            client.get(f"/range/{pw_hash[:5]}")
            client.get(f"/range/{pw_hash[:5]}", headers={"Add-Padding": "true"})
            client.get("/range/ZZZZZ")

            metrics_resp = client.get("/metrics")
            assert metrics_resp.status_code == 200
            assert (
                metrics_resp.headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8"
            )
            assert "pwned_range_requests_total 3\n" in metrics_resp.text
            assert "pwned_range_padded_responses_total 1\n" in metrics_resp.text
            assert "pwned_range_errors_total 1\n" in metrics_resp.text
            assert "pwned_range_upstream_errors_total 0\n" in metrics_resp.text
            assert "pwned_server_uptime_seconds " in metrics_resp.text

        disabled_server = create_range_server(
            host="127.0.0.1",
            port=0,
            offline_db=dump,
            enable_metrics=False,
        )
        with _running_server(disabled_server), httpx.Client(base_url=disabled_server.url) as client:
            assert disabled_server.enable_metrics is False
            resp = client.get("/metrics")
            assert resp.status_code == 404


class TestServerLifecycleAndLogging:
    def test_context_manager_properties_and_idempotent_close(self, tmp_path: Path) -> None:
        assert DEFAULT_HOST == "127.0.0.1"
        assert DEFAULT_PORT == 8080

        dump = _write_dump(tmp_path / "sha1.txt", [(_sha1_hex("password"), 1)])
        with create_range_server(host="127.0.0.1", port=0, offline_db=dump) as server:
            host, port = server.server_address
            assert host == "127.0.0.1"
            assert port > 0
            assert server.url == f"http://{host}:{port}"
            assert server.backend == "offline"
            assert server.mode == "sha1"
            assert server.access_log is False
            assert server.lookup_range(_sha1_hex("password")[:5]) == {_sha1_hex("password")[5:]: 1}
            with pytest.raises(ValueError, match="5 hexadecimal"):
                server.lookup_range("BAD")
            with pytest.raises(ValueError, match="sha1"):
                server.lookup_range(_sha1_hex("password")[:5], ntlm=True)

        # Idempotent close after context exit
        server.close()

    def test_access_log_toggle(
        self,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        dump = _write_dump(tmp_path / "sha1.txt", [])

        quiet_server = create_range_server(
            host="127.0.0.1",
            port=0,
            offline_db=dump,
            access_log=False,
        )
        with _running_server(quiet_server), httpx.Client(base_url=quiet_server.url) as client:
            assert client.get("/healthz").status_code == 200
        assert capsys.readouterr().err == ""

        loud_server = create_range_server(
            host="127.0.0.1",
            port=0,
            offline_db=dump,
            access_log=True,
        )
        with _running_server(loud_server), httpx.Client(base_url=loud_server.url) as client:
            assert client.get("/healthz").status_code == 200
        err_output = capsys.readouterr().err
        assert "GET /healthz" in err_output
