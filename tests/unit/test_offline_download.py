from __future__ import annotations

import asyncio
import hashlib
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import httpx
import pytest
from pydantic import ValidationError
from pytest_httpx import HTTPXMock

import pwned.offline_download as offline_download_module
from pwned._parsers import _md4
from pwned.client import HIBPError
from pwned.offline import OfflinePasswordsClient
from pwned.offline_download import (
    DEFAULT_INDEX_FILENAME,
    MAX_PREFIX_EXCLUSIVE,
    DownloadStats,
    _load_etags,
    download_offline_db,
)
from pwned.passwords import BASE_URL


def _sha1_hex(password: str) -> str:
    return hashlib.sha1(password.encode("utf-8")).hexdigest().upper()


def _ntlm_hex(password: str) -> str:
    return _md4(password.encode("utf-16-le")).upper()


class TestConstantsAndModels:
    def test_max_prefix_exclusive(self) -> None:
        assert MAX_PREFIX_EXCLUSIVE == 0x100000
        assert MAX_PREFIX_EXCLUSIVE == 1_048_576

    def test_default_index_filename(self) -> None:
        assert DEFAULT_INDEX_FILENAME == ".pwned-index.json"

    def test_download_stats_model(self, tmp_path: Path) -> None:
        db_path = str(tmp_path / "db.txt")
        stats = DownloadStats(
            prefixes_total=10,
            prefixes_downloaded=7,
            prefixes_cached=3,
            hashes_written=42,
            elapsed_seconds=1.25,
            output_path=db_path,
        )
        assert stats.ntlm is False
        assert stats.directory is False
        assert stats.ranges_per_second == 0.0
        assert stats.prefixes_total == 10
        assert stats.hashes_written == 42

        dir_stats = DownloadStats(
            prefixes_total=10,
            prefixes_downloaded=10,
            prefixes_cached=0,
            hashes_written=100,
            elapsed_seconds=2.0,
            ranges_per_second=5.0,
            output_path=str(tmp_path / "db_dir"),
            directory=True,
        )
        assert dir_stats.directory is True
        assert dir_stats.ranges_per_second == 5.0

        with pytest.raises(ValidationError):
            DownloadStats(
                prefixes_total=-1,
                prefixes_downloaded=0,
                prefixes_cached=0,
                hashes_written=0,
                elapsed_seconds=0.0,
                output_path=db_path,
            )

        with pytest.raises(ValidationError):
            DownloadStats(
                prefixes_total=1,
                prefixes_downloaded=1,
                prefixes_cached=0,
                hashes_written=1,
                elapsed_seconds=0.0,
                ranges_per_second=-0.5,
                output_path=db_path,
            )


class TestInputValidation:
    @pytest.mark.parametrize("concurrency", [0, -1, -10])
    def test_invalid_concurrency_raises(self, tmp_path: Path, concurrency: int) -> None:
        async def run() -> None:
            await download_offline_db(tmp_path / "db.txt", concurrency=concurrency)

        with pytest.raises(ValueError, match="concurrency must be at least 1"):
            asyncio.run(run())

    def test_invalid_max_retries_raises(self, tmp_path: Path) -> None:
        async def run() -> None:
            await download_offline_db(tmp_path / "db.txt", max_retries=-1)

        with pytest.raises(ValueError, match="max_retries must be non-negative"):
            asyncio.run(run())

    @pytest.mark.parametrize(
        ("start_prefix", "end_prefix"),
        [
            (-1, 10),
            (0, MAX_PREFIX_EXCLUSIVE + 1),
            (5, 5),
            (10, 5),
        ],
    )
    def test_invalid_prefix_range_raises(
        self, tmp_path: Path, start_prefix: int, end_prefix: int
    ) -> None:
        async def run() -> None:
            await download_offline_db(
                tmp_path / "db.txt",
                start_prefix=start_prefix,
                end_prefix=end_prefix,
            )

        with pytest.raises(ValueError, match="prefix"):
            asyncio.run(run())


class TestOverwriteBehavior:
    def test_overwrite_false_raises_when_output_exists_without_http_or_side_effects(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        output = tmp_path / "existing.txt"
        output.write_text("original content", encoding="utf-8")
        work_dir = output.parent / f".{output.name}.part"
        marker = work_dir / "marker.txt"
        marker.parent.mkdir(parents=True, exist_ok=True)
        marker.write_text("keep", encoding="utf-8")

        async def run() -> None:
            await download_offline_db(
                output,
                start_prefix=0,
                end_prefix=2,
                resume=False,
                overwrite=False,
            )

        with pytest.raises(
            FileExistsError,
            match=r"Output file already exists:.*--overwrite",
        ):
            asyncio.run(run())

        assert httpx_mock.get_requests() == []
        assert output.read_text(encoding="utf-8") == "original content"
        assert marker.read_text(encoding="utf-8") == "keep"

    def test_overwrite_false_succeeds_when_output_does_not_exist(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", text=f"{'A' * 35}:5\n")
        output = tmp_path / "fresh.txt"

        async def run() -> DownloadStats:
            return await download_offline_db(
                output,
                start_prefix=0,
                end_prefix=1,
                overwrite=False,
            )

        stats = asyncio.run(run())
        assert stats.prefixes_downloaded == 1
        assert stats.hashes_written == 1
        assert output.read_bytes() == f"00000{'A' * 35}:5\r\n".encode("ascii")

    def test_overwrite_true_replaces_existing_file(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", text=f"{'B' * 35}:9\n")
        output = tmp_path / "existing.txt"
        output.write_text("stale content", encoding="utf-8")

        async def run() -> DownloadStats:
            return await download_offline_db(
                output,
                start_prefix=0,
                end_prefix=1,
                overwrite=True,
            )

        stats = asyncio.run(run())
        assert stats.prefixes_downloaded == 1
        assert stats.hashes_written == 1
        assert output.read_bytes() == f"00000{'B' * 35}:9\r\n".encode("ascii")

    @pytest.mark.parametrize("overwrite", [False, True])
    def test_single_file_mode_raises_is_a_directory_error_when_output_is_dir(
        self, tmp_path: Path, httpx_mock: HTTPXMock, overwrite: bool
    ) -> None:
        existing_dir = tmp_path / "existing_dir"
        existing_dir.mkdir()

        async def run() -> None:
            await download_offline_db(
                existing_dir,
                start_prefix=0,
                end_prefix=1,
                overwrite=overwrite,
            )

        with pytest.raises(IsADirectoryError, match="Output path is a directory:"):
            asyncio.run(run())

        assert httpx_mock.get_requests() == []


class TestBasicDownloadAndOfflineIntegration:
    def test_sha1_download_sorts_normalizes_and_works_with_offline_client(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        pw_digest = _sha1_hex("password")
        pw_prefix_int = int(pw_digest[:5], 16)
        pw_suffix = pw_digest[5:]
        next_prefix = f"{pw_prefix_int + 1:05X}"

        # Intentionally unsorted, lowercase suffixes, plus padded :0 entry to strip.
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/{pw_prefix_int:05X}",
            text=(f"{pw_suffix.lower()}:3861493\r\n{'0' * 35}:5\n{'F' * 35}:0\n"),
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/{next_prefix}",
            text=f"{'A' * 35}:12\n",
        )

        output = tmp_path / "nested" / "sha1.txt"
        progress_events: list[tuple[int, int]] = []

        async def run() -> DownloadStats:
            return await download_offline_db(
                output,
                start_prefix=pw_prefix_int,
                end_prefix=pw_prefix_int + 2,
                user_agent="custom-agent/1.0",
                on_progress=lambda done, total: progress_events.append((done, total)),
            )

        stats = asyncio.run(run())

        assert stats.prefixes_total == 2
        assert stats.prefixes_downloaded == 2
        assert stats.prefixes_cached == 0
        assert stats.hashes_written == 3
        assert stats.elapsed_seconds >= 0.0
        assert stats.output_path == str(output)
        assert stats.ntlm is False

        # Progress callback fired for each completed prefix.
        assert len(progress_events) == 2
        assert sorted(progress_events) == [(1, 2), (2, 2)]

        # Work directory cleaned up when etag_cache_path is None.
        work_dir = output.parent / f".{output.name}.part"
        assert not work_dir.exists()

        # Verify CRLF sorted output format.
        expected_lines = sorted(
            [
                f"{pw_prefix_int:05X}{'0' * 35}:5",
                f"{pw_digest}:3861493",
                f"{next_prefix}{'A' * 35}:12",
            ]
        )
        assert output.read_bytes() == ("\r\n".join(expected_lines) + "\r\n").encode("ascii")

        # Verify custom User-Agent header sent.
        requests = httpx_mock.get_requests()
        assert all(req.headers["User-Agent"] == "custom-agent/1.0" for req in requests)

        # End-to-end verification with OfflinePasswordsClient.
        with OfflinePasswordsClient(output) as client:
            assert client.check_password("password") == 3861493
            assert client.is_pwned("password") is True
            assert client.check_hash(f"{next_prefix}{'A' * 35}") == 12
            assert client.check_password("definitely-not-in-db") == 0

    def test_ntlm_download_and_offline_client(self, tmp_path: Path, httpx_mock: HTTPXMock) -> None:
        ntlm_digest = _ntlm_hex("letmein")
        prefix_int = int(ntlm_digest[:5], 16)
        suffix = ntlm_digest[5:]

        httpx_mock.add_response(
            url=httpx.URL(f"{BASE_URL}/range/{prefix_int:05X}", params={"mode": "ntlm"}),
            text=f"{suffix}:9001\n",
        )

        output = tmp_path / "ntlm.txt"

        async def run() -> DownloadStats:
            return await download_offline_db(
                output,
                ntlm=True,
                start_prefix=prefix_int,
                end_prefix=prefix_int + 1,
            )

        stats = asyncio.run(run())

        assert stats.ntlm is True
        assert stats.hashes_written == 1
        assert stats.prefixes_downloaded == 1

        with OfflinePasswordsClient(output, ntlm=True) as client:
            assert client.check_password("letmein") == 9001
            assert client.check_password("other") == 0

    def test_empty_shards_produce_empty_output_file(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", text="")
        httpx_mock.add_response(url=f"{BASE_URL}/range/00001", text=f"{'0' * 35}:0\n")

        output = tmp_path / "empty.txt"

        async def run() -> DownloadStats:
            return await download_offline_db(output, start_prefix=0, end_prefix=2)

        stats = asyncio.run(run())
        assert stats.hashes_written == 0
        assert output.read_bytes() == b""
        with OfflinePasswordsClient(output) as client:
            assert client.check_password("password") == 0

    def test_ranges_per_second_computed_from_elapsed(
        self, tmp_path: Path, httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        for i in range(3):
            httpx_mock.add_response(url=f"{BASE_URL}/range/{i:05X}", text=f"{'A' * 35}:1\n")

        ticks = iter([100.0, 102.0])
        monkeypatch.setattr(
            offline_download_module,
            "time",
            SimpleNamespace(monotonic=lambda: next(ticks)),
        )

        output = tmp_path / "timed.txt"

        async def run() -> DownloadStats:
            return await download_offline_db(output, start_prefix=0, end_prefix=3)

        stats = asyncio.run(run())
        assert stats.elapsed_seconds == 2.0
        assert stats.ranges_per_second == 1.5
        assert stats.directory is False

    def test_ranges_per_second_zero_when_elapsed_is_zero(
        self, tmp_path: Path, httpx_mock: HTTPXMock, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", text=f"{'A' * 35}:1\n")
        monkeypatch.setattr(
            offline_download_module,
            "time",
            SimpleNamespace(monotonic=lambda: 42.0),
        )

        output = tmp_path / "zero_elapsed.txt"

        async def run() -> DownloadStats:
            return await download_offline_db(output, start_prefix=0, end_prefix=1)

        stats = asyncio.run(run())
        assert stats.elapsed_seconds == 0.0
        assert stats.ranges_per_second == 0.0


class TestResumeAndETags:
    def test_resume_without_etag_skips_existing_shards(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        output = tmp_path / "sha1.txt"
        work_dir = output.parent / f".{output.name}.part"
        existing_shard = work_dir / "00" / "00000.txt"
        existing_shard.parent.mkdir(parents=True, exist_ok=True)
        existing_shard.write_text(f"{'1' * 35}:7\n", encoding="utf-8")

        # Only 00001 should be requested over HTTP.
        httpx_mock.add_response(url=f"{BASE_URL}/range/00001", text=f"{'2' * 35}:8\n")

        progress: list[tuple[int, int]] = []

        async def run() -> DownloadStats:
            return await download_offline_db(
                output,
                start_prefix=0,
                end_prefix=2,
                resume=True,
                on_progress=lambda done, total: progress.append((done, total)),
            )

        stats = asyncio.run(run())

        assert sorted(progress) == [(1, 2), (2, 2)]

        assert stats.prefixes_total == 2
        assert stats.prefixes_cached == 1
        assert stats.prefixes_downloaded == 1
        assert stats.hashes_written == 2
        assert len(httpx_mock.get_requests()) == 1
        assert not work_dir.exists()

        with OfflinePasswordsClient(output) as client:
            assert client.check_hash(f"00000{'1' * 35}") == 7
            assert client.check_hash(f"00001{'2' * 35}") == 8

    def test_resume_false_cleans_existing_work_dir(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        output = tmp_path / "sha1.txt"
        work_dir = output.parent / f".{output.name}.part"
        stale_shard = work_dir / "00" / "00000.txt"
        stale_shard.parent.mkdir(parents=True, exist_ok=True)
        stale_shard.write_text(f"{'9' * 35}:999\n", encoding="utf-8")

        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", text=f"{'1' * 35}:10\n")

        async def run() -> DownloadStats:
            return await download_offline_db(output, start_prefix=0, end_prefix=1, resume=False)

        stats = asyncio.run(run())
        assert stats.prefixes_cached == 0
        assert stats.prefixes_downloaded == 1
        assert stats.hashes_written == 1
        assert not work_dir.exists()

        with OfflinePasswordsClient(output) as client:
            assert client.check_hash(f"00000{'9' * 35}") == 0
            assert client.check_hash(f"00000{'1' * 35}") == 10

    def test_etag_revalidation_304_200_and_missing_etag(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        output = tmp_path / "sha1.txt"
        etag_cache = tmp_path / "cache" / "etags.json"

        # Initial download:
        # 00000 -> ETag "e0"
        # 00001 -> ETag "e1"
        # 00002 -> No ETag header
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00000",
            text=f"{'A' * 35}:1\n",
            headers={"ETag": '"e0"'},
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00001",
            text=f"{'B' * 35}:2\n",
            headers={"ETag": '"e1"'},
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00002",
            text=f"{'C' * 35}:3\n",
        )

        async def run_once() -> DownloadStats:
            return await download_offline_db(
                output,
                start_prefix=0,
                end_prefix=3,
                etag_cache_path=etag_cache,
            )

        stats1 = asyncio.run(run_once())
        assert stats1.prefixes_downloaded == 3
        assert stats1.prefixes_cached == 0

        # work_dir is preserved when etag_cache_path is set.
        work_dir = output.parent / f".{output.name}.part"
        assert work_dir.exists()
        assert json.loads(etag_cache.read_text(encoding="utf-8")) == {
            "00000": '"e0"',
            "00001": '"e1"',
        }

        # Second run with resume=True:
        # 00000 -> 304 Not Modified (cached)
        # 00001 -> 200 OK with updated body & new ETag "e1-new"
        # 00002 -> had no stored ETag, fetches fresh without If-None-Match and gets ETag "e2"
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", status_code=304)
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00001",
            text=f"{'B' * 35}:22\n",
            headers={"ETag": '"e1-new"'},
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00002",
            text=f"{'C' * 35}:33\n",
            headers={"ETag": '"e2"'},
        )

        stats2 = asyncio.run(run_once())
        assert stats2.prefixes_total == 3
        assert stats2.prefixes_cached == 1
        assert stats2.prefixes_downloaded == 2
        assert stats2.hashes_written == 3

        reqs = httpx_mock.get_requests()[3:]
        by_path = {req.url.path: req for req in reqs}
        assert by_path["/range/00000"].headers["If-None-Match"] == '"e0"'
        assert by_path["/range/00001"].headers["If-None-Match"] == '"e1"'
        assert "If-None-Match" not in by_path["/range/00002"].headers

        assert json.loads(etag_cache.read_text(encoding="utf-8")) == {
            "00000": '"e0"',
            "00001": '"e1-new"',
            "00002": '"e2"',
        }

        with OfflinePasswordsClient(output) as client:
            assert client.check_hash(f"00000{'A' * 35}") == 1
            assert client.check_hash(f"00001{'B' * 35}") == 22
            assert client.check_hash(f"00002{'C' * 35}") == 33

    @pytest.mark.parametrize(
        "corrupt_content",
        [
            "{not valid json",
            '["a", "list"]',
        ],
    )
    def test_corrupt_etag_cache_falls_back_gracefully(
        self, tmp_path: Path, httpx_mock: HTTPXMock, corrupt_content: str
    ) -> None:
        output = tmp_path / "sha1.txt"
        etag_cache = tmp_path / "etags.json"
        etag_cache.write_text(corrupt_content, encoding="utf-8")

        work_dir = output.parent / f".{output.name}.part"
        shard = work_dir / "00" / "00000.txt"
        shard.parent.mkdir(parents=True, exist_ok=True)
        shard.write_text(f"{'A' * 35}:1\n", encoding="utf-8")

        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00000",
            text=f"{'A' * 35}:5\n",
            headers={"ETag": '"fresh"'},
        )

        async def run() -> DownloadStats:
            return await download_offline_db(
                output,
                start_prefix=0,
                end_prefix=1,
                etag_cache_path=etag_cache,
            )

        stats = asyncio.run(run())
        assert stats.prefixes_downloaded == 1
        assert json.loads(etag_cache.read_text(encoding="utf-8")) == {"00000": '"fresh"'}

    def test_load_etags_filters_non_strings_and_handles_oserror(self, tmp_path: Path) -> None:
        mixed_file = tmp_path / "mixed.json"
        mixed_file.write_text('{"00000": "etag0", "00001": 123}', encoding="utf-8")
        assert _load_etags(mixed_file) == {"00000": "etag0"}

        # Directory path triggers OSError on read_text.
        assert _load_etags(tmp_path) == {}

    def test_single_file_force_ignores_cached_shards_without_etag_cache(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        output = tmp_path / "sha1.txt"
        work_dir = output.parent / f".{output.name}.part"
        stale_shard = work_dir / "00" / "00000.txt"
        stale_shard.parent.mkdir(parents=True, exist_ok=True)
        stale_shard.write_text(f"{'9' * 35}:999\n", encoding="utf-8")

        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", text=f"{'1' * 35}:10\n")

        async def run() -> DownloadStats:
            return await download_offline_db(
                output,
                start_prefix=0,
                end_prefix=1,
                resume=True,
                force=True,
            )

        stats = asyncio.run(run())
        assert stats.prefixes_cached == 0
        assert stats.prefixes_downloaded == 1
        assert stats.hashes_written == 1
        assert not work_dir.exists()

        with OfflinePasswordsClient(output) as client:
            assert client.check_hash(f"00000{'9' * 35}") == 0
            assert client.check_hash(f"00000{'1' * 35}") == 10

    def test_single_file_force_ignores_saved_etags_and_rebuilds_cache(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        output = tmp_path / "sha1.txt"
        etag_cache = tmp_path / "etags.json"
        etag_cache.write_text(json.dumps({"00000": '"old-etag"'}), encoding="utf-8")

        work_dir = output.parent / f".{output.name}.part"
        stale_shard = work_dir / "00" / "00000.txt"
        stale_shard.parent.mkdir(parents=True, exist_ok=True)
        stale_shard.write_text(f"{'A' * 35}:1\n", encoding="utf-8")

        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00000",
            text=f"{'A' * 35}:55\n",
            headers={"ETag": '"new-etag"'},
        )

        async def run() -> DownloadStats:
            return await download_offline_db(
                output,
                start_prefix=0,
                end_prefix=1,
                resume=True,
                force=True,
                etag_cache_path=etag_cache,
            )

        stats = asyncio.run(run())
        assert stats.prefixes_cached == 0
        assert stats.prefixes_downloaded == 1
        assert stats.hashes_written == 1

        reqs = httpx_mock.get_requests()
        assert len(reqs) == 1
        assert "If-None-Match" not in reqs[0].headers
        assert json.loads(etag_cache.read_text(encoding="utf-8")) == {"00000": '"new-etag"'}
        with OfflinePasswordsClient(output) as client:
            assert client.check_hash(f"00000{'A' * 35}") == 55


class TestDirectoryMode:
    def test_directory_download_writes_flat_shards_and_index(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00000",
            text=f"{'A' * 35}:10\r\n{'0' * 35}:0\r\n",
            headers={"ETag": '"e0"'},
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00001",
            text=f"{'B' * 35}:20\n{'C' * 35}:30\n",
            headers={"ETag": '"e1"'},
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00002",
            text=f"{'D' * 35}:40\n",
        )

        output_dir = tmp_path / "hibp_shards"

        async def run() -> DownloadStats:
            return await download_offline_db(
                output_dir,
                start_prefix=0,
                end_prefix=3,
                directory=True,
            )

        stats = asyncio.run(run())

        assert stats.directory is True
        assert stats.prefixes_total == 3
        assert stats.prefixes_downloaded == 3
        assert stats.prefixes_cached == 0
        assert stats.hashes_written == 4
        assert stats.ranges_per_second >= 0.0
        assert stats.output_path == str(output_dir)

        assert (output_dir / "00000.txt").read_bytes() == (
            f"{'A' * 35}:10\r\n{'0' * 35}:0\r\n".encode("ascii")
        )
        assert (output_dir / "00001.txt").read_text(encoding="utf-8") == (
            f"{'B' * 35}:20\n{'C' * 35}:30\n"
        )
        assert (output_dir / "00002.txt").read_text(encoding="utf-8") == f"{'D' * 35}:40\n"

        index_path = output_dir / DEFAULT_INDEX_FILENAME
        assert json.loads(index_path.read_text(encoding="utf-8")) == {
            "00000": '"e0"',
            "00001": '"e1"',
        }
        # No .part work directory created in directory mode.
        assert not (tmp_path / f".{output_dir.name}.part").exists()

    def test_directory_mode_custom_etag_cache_path(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00000",
            text=f"{'A' * 35}:1\n",
            headers={"ETag": '"custom-e0"'},
        )
        output_dir = tmp_path / "shards"
        custom_index = tmp_path / "meta" / "index.json"

        async def run() -> DownloadStats:
            return await download_offline_db(
                output_dir,
                start_prefix=0,
                end_prefix=1,
                directory=True,
                etag_cache_path=custom_index,
            )

        stats = asyncio.run(run())
        assert stats.directory is True
        assert stats.hashes_written == 1
        assert json.loads(custom_index.read_text(encoding="utf-8")) == {"00000": '"custom-e0"'}
        assert not (output_dir / DEFAULT_INDEX_FILENAME).exists()

    def test_directory_incremental_refresh_handles_304_200_and_missing_etag(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        output_dir = tmp_path / "hibp_dir"

        # Initial download:
        # 00000 -> ETag "e0"
        # 00001 -> ETag "e1"
        # 00002 -> No ETag header
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00000",
            text=f"{'A' * 35}:1\n{'E' * 35}:4\n",
            headers={"ETag": '"e0"'},
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00001",
            text=f"{'B' * 35}:2\n",
            headers={"ETag": '"e1"'},
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00002",
            text=f"{'C' * 35}:3\n",
        )

        async def run_download(*, overwrite: bool = True) -> DownloadStats:
            return await download_offline_db(
                output_dir,
                start_prefix=0,
                end_prefix=3,
                directory=True,
                overwrite=overwrite,
            )

        stats1 = asyncio.run(run_download(overwrite=False))
        assert stats1.directory is True
        assert stats1.prefixes_downloaded == 3
        assert stats1.prefixes_cached == 0
        assert stats1.hashes_written == 4

        # Second run on existing indexed directory (even with overwrite=False):
        # 00000 -> 304 Not Modified (cached, original file untouched)
        # 00001 -> 200 OK with updated content and ETag "e1-new"
        # 00002 -> no ETag in index -> fetched fresh without If-None-Match, gets "e2"
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", status_code=304)
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00001",
            text=f"{'B' * 35}:22\n{'F' * 35}:99\n",
            headers={"ETag": '"e1-new"'},
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00002",
            text=f"{'C' * 35}:33\n",
            headers={"ETag": '"e2"'},
        )

        stats2 = asyncio.run(run_download(overwrite=False))
        assert stats2.directory is True
        assert stats2.prefixes_total == 3
        assert stats2.prefixes_cached == 1
        assert stats2.prefixes_downloaded == 2
        assert stats2.hashes_written == 5

        reqs = httpx_mock.get_requests()[3:]
        by_path = {req.url.path: req for req in reqs}
        assert by_path["/range/00000"].headers["If-None-Match"] == '"e0"'
        assert by_path["/range/00001"].headers["If-None-Match"] == '"e1"'
        assert "If-None-Match" not in by_path["/range/00002"].headers

        index_path = output_dir / DEFAULT_INDEX_FILENAME
        assert json.loads(index_path.read_text(encoding="utf-8")) == {
            "00000": '"e0"',
            "00001": '"e1-new"',
            "00002": '"e2"',
        }
        assert (output_dir / "00000.txt").read_text(encoding="utf-8") == (
            f"{'A' * 35}:1\n{'E' * 35}:4\n"
        )
        assert (output_dir / "00001.txt").read_text(encoding="utf-8") == (
            f"{'B' * 35}:22\n{'F' * 35}:99\n"
        )
        assert (output_dir / "00002.txt").read_text(encoding="utf-8") == f"{'C' * 35}:33\n"

    def test_directory_force_ignores_saved_etags_and_rebuilds_index(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        output_dir = tmp_path / "hibp_dir"

        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00000",
            text=f"{'A' * 35}:1\n",
            headers={"ETag": '"e0"'},
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00001",
            text=f"{'B' * 35}:2\n",
            headers={"ETag": '"e1"'},
        )

        async def run_initial() -> DownloadStats:
            return await download_offline_db(
                output_dir,
                start_prefix=0,
                end_prefix=2,
                directory=True,
            )

        asyncio.run(run_initial())

        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00000",
            text=f"{'A' * 35}:100\n",
            headers={"ETag": '"e0-fresh"'},
        )
        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00001",
            text=f"{'B' * 35}:200\n",
        )

        async def run_force() -> DownloadStats:
            return await download_offline_db(
                output_dir,
                start_prefix=0,
                end_prefix=2,
                directory=True,
                force=True,
            )

        stats = asyncio.run(run_force())
        assert stats.directory is True
        assert stats.prefixes_cached == 0
        assert stats.prefixes_downloaded == 2
        assert stats.hashes_written == 2

        reqs = httpx_mock.get_requests()[2:]
        assert all("If-None-Match" not in req.headers for req in reqs)

        index_path = output_dir / DEFAULT_INDEX_FILENAME
        assert json.loads(index_path.read_text(encoding="utf-8")) == {"00000": '"e0-fresh"'}
        assert (output_dir / "00000.txt").read_text(encoding="utf-8") == f"{'A' * 35}:100\n"
        assert (output_dir / "00001.txt").read_text(encoding="utf-8") == f"{'B' * 35}:200\n"

    def test_directory_resume_false_ignores_saved_etags(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        output_dir = tmp_path / "hibp_dir"
        output_dir.mkdir()
        (output_dir / "00000.txt").write_text(f"{'A' * 35}:1\n", encoding="utf-8")
        index_path = output_dir / DEFAULT_INDEX_FILENAME
        index_path.write_text(json.dumps({"00000": '"old"'}), encoding="utf-8")

        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00000",
            text=f"{'A' * 35}:77\n",
            headers={"ETag": '"rebuilt"'},
        )

        async def run() -> DownloadStats:
            return await download_offline_db(
                output_dir,
                start_prefix=0,
                end_prefix=1,
                directory=True,
                resume=False,
            )

        stats = asyncio.run(run())
        assert stats.prefixes_cached == 0
        assert stats.prefixes_downloaded == 1
        reqs = httpx_mock.get_requests()
        assert len(reqs) == 1
        assert "If-None-Match" not in reqs[0].headers
        assert json.loads(index_path.read_text(encoding="utf-8")) == {"00000": '"rebuilt"'}

    @pytest.mark.parametrize("overwrite", [False, True])
    def test_directory_safety_existing_file_raises_file_exists_error(
        self, tmp_path: Path, httpx_mock: HTTPXMock, overwrite: bool
    ) -> None:
        existing_file = tmp_path / "not_a_dir.txt"
        existing_file.write_text("keep me", encoding="utf-8")

        async def run() -> None:
            await download_offline_db(
                existing_file,
                start_prefix=0,
                end_prefix=1,
                directory=True,
                overwrite=overwrite,
            )

        with pytest.raises(FileExistsError, match="Output path is an existing file:"):
            asyncio.run(run())

        assert httpx_mock.get_requests() == []
        assert existing_file.read_text(encoding="utf-8") == "keep me"

    def test_directory_safety_non_empty_without_index_raises_when_overwrite_false(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        output_dir = tmp_path / "non_empty"
        output_dir.mkdir()
        (output_dir / "stray.txt").write_text("stray", encoding="utf-8")

        async def run() -> None:
            await download_offline_db(
                output_dir,
                start_prefix=0,
                end_prefix=1,
                directory=True,
                overwrite=False,
            )

        with pytest.raises(
            FileExistsError,
            match=r"Output directory is not empty and has no saved index:.*--overwrite",
        ):
            asyncio.run(run())

        assert httpx_mock.get_requests() == []

    def test_directory_safety_non_empty_without_index_succeeds_when_overwrite_true(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        output_dir = tmp_path / "non_empty"
        output_dir.mkdir()
        (output_dir / "stray.txt").write_text("stray", encoding="utf-8")

        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00000",
            text=f"{'A' * 35}:5\n",
            headers={"ETag": '"e0"'},
        )

        async def run() -> DownloadStats:
            return await download_offline_db(
                output_dir,
                start_prefix=0,
                end_prefix=1,
                directory=True,
                overwrite=True,
            )

        stats = asyncio.run(run())
        assert stats.directory is True
        assert stats.prefixes_downloaded == 1
        assert stats.hashes_written == 1
        assert (output_dir / "00000.txt").read_text(encoding="utf-8") == f"{'A' * 35}:5\n"
        index_path = output_dir / DEFAULT_INDEX_FILENAME
        assert json.loads(index_path.read_text(encoding="utf-8")) == {"00000": '"e0"'}

    def test_directory_safety_empty_existing_directory_succeeds_when_overwrite_false(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        output_dir = tmp_path / "empty_dir"
        output_dir.mkdir()

        httpx_mock.add_response(
            url=f"{BASE_URL}/range/00000",
            text=f"{'A' * 35}:7\n",
            headers={"ETag": '"e0"'},
        )

        async def run() -> DownloadStats:
            return await download_offline_db(
                output_dir,
                start_prefix=0,
                end_prefix=1,
                directory=True,
                overwrite=False,
            )

        stats = asyncio.run(run())
        assert stats.directory is True
        assert stats.prefixes_downloaded == 1
        assert stats.hashes_written == 1
        assert (output_dir / "00000.txt").read_text(encoding="utf-8") == f"{'A' * 35}:7\n"


class TestRetriesErrorsAndConcurrency:
    def test_retries_with_exponential_backoff_and_cap(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        # 7 failures (429, 500, RequestError, 502, 503, 504, 429) then 200 OK.
        # Backoff delays: 0.5, 1.0, 2.0, 4.0, 8.0, 10.0, 10.0.
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", status_code=429)
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", status_code=500)
        httpx_mock.add_exception(
            httpx.ConnectError("boom"),
            url=f"{BASE_URL}/range/00000",
        )
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", status_code=502)
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", status_code=503)
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", status_code=504)
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", status_code=429)
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", text=f"{'A' * 35}:42\n")

        sleeps: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)

        output = tmp_path / "db.txt"

        async def run() -> DownloadStats:
            return await download_offline_db(
                output,
                start_prefix=0,
                end_prefix=1,
                max_retries=7,
                sleep=fake_sleep,
            )

        stats = asyncio.run(run())
        assert stats.hashes_written == 1
        assert sleeps == [0.5, 1.0, 2.0, 4.0, 8.0, 10.0, 10.0]

    def test_unlimited_retries_when_max_retries_is_none(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        # 5 transient failures (past default MAX_RETRIES=3), covering both
        # httpx.RequestError and HTTP 429/5xx paths, followed by 200 OK.
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", status_code=503)
        httpx_mock.add_exception(
            httpx.ConnectError("transient"),
            url=f"{BASE_URL}/range/00000",
        )
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", status_code=429)
        httpx_mock.add_exception(
            httpx.ReadTimeout("slow"),
            url=f"{BASE_URL}/range/00000",
        )
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", status_code=503)
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", text=f"{'A' * 35}:123\n")

        sleeps: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)

        output = tmp_path / "unlimited.txt"

        async def run() -> DownloadStats:
            return await download_offline_db(
                output,
                start_prefix=0,
                end_prefix=1,
                max_retries=None,
                sleep=fake_sleep,
            )

        stats = asyncio.run(run())
        assert stats.prefixes_downloaded == 1
        assert stats.hashes_written == 1
        assert sleeps == [0.5, 1.0, 2.0, 4.0, 8.0]

    def test_retry_exhaustion_on_http_500_raises_hibp_error(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", status_code=500)
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", status_code=500)

        sleeps: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)

        async def run() -> None:
            await download_offline_db(
                tmp_path / "db.txt",
                start_prefix=0,
                end_prefix=1,
                max_retries=1,
                sleep=fake_sleep,
            )

        with pytest.raises(HIBPError, match="HTTP 500"):
            asyncio.run(run())
        assert sleeps == [0.5]

    def test_retry_exhaustion_on_request_error_raises_hibp_error(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_exception(httpx.ReadTimeout("timeout"), url=f"{BASE_URL}/range/00000")

        async def fake_sleep(_seconds: float) -> None:
            return None

        async def run() -> None:
            await download_offline_db(
                tmp_path / "db.txt",
                start_prefix=0,
                end_prefix=1,
                max_retries=0,
                sleep=fake_sleep,
            )

        with pytest.raises(HIBPError, match="Request failed"):
            asyncio.run(run())

    @pytest.mark.parametrize("status_code", [400, 403, 404, 304])
    def test_non_retryable_status_raises_hibp_error_without_sleep(
        self, tmp_path: Path, httpx_mock: HTTPXMock, status_code: int
    ) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", status_code=status_code)

        sleeps: list[float] = []

        async def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)

        async def run() -> None:
            await download_offline_db(
                tmp_path / "db.txt",
                start_prefix=0,
                end_prefix=1,
                max_retries=3,
                sleep=fake_sleep,
            )

        with pytest.raises(HIBPError, match=f"HTTP {status_code}"):
            asyncio.run(run())
        assert sleeps == []

    def test_external_client_not_closed_and_concurrency_bounded(self, tmp_path: Path) -> None:
        in_flight = 0
        max_seen = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal in_flight, max_seen
            in_flight += 1
            max_seen = max(max_seen, in_flight)
            await asyncio.sleep(0.01)
            in_flight -= 1
            return httpx.Response(200, text=f"{'A' * 35}:1\n")

        transport = httpx.MockTransport(handler)
        output = tmp_path / "db.txt"

        async def run() -> None:
            ext_client = httpx.AsyncClient(base_url=BASE_URL, transport=transport)
            stats = await download_offline_db(
                output,
                start_prefix=0,
                end_prefix=6,
                concurrency=2,
                client=ext_client,
            )
            assert stats.prefixes_downloaded == 6
            assert not ext_client.is_closed
            await ext_client.aclose()

        asyncio.run(run())
        assert max_seen <= 2
        assert max_seen == 2

    def test_bounded_worker_pool_spawns_only_concurrency_tasks(self, tmp_path: Path) -> None:
        in_flight = 0
        max_seen = 0

        async def handler(request: httpx.Request) -> httpx.Response:
            nonlocal in_flight, max_seen
            in_flight += 1
            max_seen = max(max_seen, in_flight)
            prefix = request.url.path.rsplit("/", 1)[-1]
            prefix_int = int(prefix, 16)
            await asyncio.sleep(0)
            in_flight -= 1
            return httpx.Response(200, text=f"{prefix_int:035X}:{prefix_int + 1}\n")

        transport = httpx.MockTransport(handler)
        output = tmp_path / "pool.txt"
        progress_events: list[tuple[int, int]] = []

        async def run() -> tuple[DownloadStats, int]:
            async with httpx.AsyncClient(base_url=BASE_URL, transport=transport) as ext_client:
                with patch.object(
                    asyncio, "create_task", wraps=asyncio.create_task
                ) as spy_create_task:
                    stats = await download_offline_db(
                        output,
                        start_prefix=0,
                        end_prefix=16,
                        concurrency=2,
                        client=ext_client,
                        on_progress=lambda done, total: progress_events.append((done, total)),
                    )
                    return stats, spy_create_task.call_count

        stats, task_count = asyncio.run(run())
        assert task_count == 2
        assert max_seen <= 2
        assert stats.prefixes_total == 16
        assert stats.prefixes_downloaded == 16
        assert stats.prefixes_cached == 0
        assert stats.hashes_written == 16
        assert progress_events == [(i, 16) for i in range(1, 17)]

        expected_lines = [f"{i:05X}{i:035X}:{i + 1}" for i in range(16)]
        assert output.read_bytes() == ("\r\n".join(expected_lines) + "\r\n").encode("ascii")

    def test_bounded_worker_pool_caps_workers_to_total_prefixes(self, tmp_path: Path) -> None:
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, text=f"{'A' * 35}:1\n")

        transport = httpx.MockTransport(handler)
        output = tmp_path / "small.txt"

        async def run() -> tuple[DownloadStats, int]:
            async with httpx.AsyncClient(base_url=BASE_URL, transport=transport) as ext_client:
                with patch.object(
                    asyncio, "create_task", wraps=asyncio.create_task
                ) as spy_create_task:
                    stats = await download_offline_db(
                        output,
                        start_prefix=0,
                        end_prefix=3,
                        concurrency=32,
                        client=ext_client,
                    )
                    return stats, spy_create_task.call_count

        stats, task_count = asyncio.run(run())
        assert task_count == 3
        assert stats.prefixes_total == 3
        assert stats.prefixes_downloaded == 3
        assert stats.hashes_written == 3

    def test_worker_error_cancels_sibling_workers_and_stops_remaining_prefixes(
        self, tmp_path: Path
    ) -> None:
        requested_prefixes: list[str] = []
        sibling_cancelled = False
        output = tmp_path / "cancelled.txt"

        async def run() -> None:
            nonlocal sibling_cancelled
            sibling_started = asyncio.Event()

            async def handler(request: httpx.Request) -> httpx.Response:
                nonlocal sibling_cancelled
                prefix = request.url.path.rsplit("/", 1)[-1]
                requested_prefixes.append(prefix)
                if prefix == "00001":
                    sibling_started.set()
                    try:
                        await asyncio.sleep(10)
                    except asyncio.CancelledError:
                        sibling_cancelled = True
                        raise
                await sibling_started.wait()
                return httpx.Response(400)

            transport = httpx.MockTransport(handler)
            async with httpx.AsyncClient(base_url=BASE_URL, transport=transport) as ext_client:
                await download_offline_db(
                    output,
                    start_prefix=0,
                    end_prefix=16,
                    concurrency=2,
                    client=ext_client,
                )

        with pytest.raises(HIBPError, match="HTTP 400"):
            asyncio.run(run())

        assert sibling_cancelled is True
        assert set(requested_prefixes) == {"00000", "00001"}
        assert not output.exists()

    def test_task_cancellation_when_one_prefix_fails(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", status_code=400)
        httpx_mock.add_response(url=f"{BASE_URL}/range/00001", status_code=500)

        async def slow_sleep(_seconds: float) -> None:
            await asyncio.sleep(10)

        async def run() -> None:
            await download_offline_db(
                tmp_path / "db.txt",
                start_prefix=0,
                end_prefix=2,
                concurrency=2,
                max_retries=2,
                sleep=slow_sleep,
            )

        with pytest.raises(HIBPError, match="HTTP 400"):
            asyncio.run(run())

    def test_atomic_write_error_cleans_up_temp_file(
        self, tmp_path: Path, httpx_mock: HTTPXMock
    ) -> None:
        httpx_mock.add_response(url=f"{BASE_URL}/range/00000", text=f"{'A' * 35}:1\n")
        output = tmp_path / "db.txt"
        output.write_text("existing", encoding="utf-8")

        async def run() -> None:
            with patch.object(os, "replace", side_effect=OSError("disk full")):
                await download_offline_db(output, start_prefix=0, end_prefix=1)

        with pytest.raises(OSError, match="disk full"):
            asyncio.run(run())

        # Original file preserved and no leftover .tmp files.
        assert output.read_text(encoding="utf-8") == "existing"
        assert list(tmp_path.glob("*.tmp")) == []
