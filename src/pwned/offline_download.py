from __future__ import annotations

import asyncio
import contextlib
import json
import os
import shutil
import tempfile
import time
from collections.abc import Awaitable, Callable, Iterator
from pathlib import Path
from typing import IO

import httpx
from pydantic import Field

from pwned._parsers import _parse_range_response
from pwned.client import MAX_RETRIES, REQUEST_TIMEOUT, HIBPError
from pwned.config import DEFAULT_USER_AGENT
from pwned.models import NonNegativeInt, _HIBPBase
from pwned.passwords import BASE_URL

MAX_PREFIX_EXCLUSIVE = 0x100000
DEFAULT_INDEX_FILENAME = ".pwned-index.json"
ETAG_CHECKPOINT_INTERVAL = 32_768


class DownloadStats(_HIBPBase):
    """Summary statistics returned by :func:`download_offline_db`."""

    prefixes_total: NonNegativeInt
    prefixes_downloaded: NonNegativeInt
    prefixes_cached: NonNegativeInt
    hashes_written: NonNegativeInt
    elapsed_seconds: float = Field(ge=0.0)
    ranges_per_second: float = Field(default=0.0, ge=0.0)
    output_path: str
    ntlm: bool = False
    directory: bool = False


def _validate_options(
    *,
    concurrency: int,
    max_retries: int | None,
    start_prefix: int,
    end_prefix: int,
) -> None:
    if concurrency < 1:
        raise ValueError("concurrency must be at least 1")
    if max_retries is not None and max_retries < 0:
        raise ValueError("max_retries must be non-negative")
    if start_prefix < 0 or end_prefix > MAX_PREFIX_EXCLUSIVE or start_prefix >= end_prefix:
        raise ValueError(
            "start_prefix and end_prefix must satisfy "
            f"0 <= start_prefix < end_prefix <= 0x{MAX_PREFIX_EXCLUSIVE:X}"
        )


def _load_index(path: Path) -> tuple[dict[str, str], str | None]:
    """Load (etags, mode) from an index/ETag JSON file, returning ({}, None) if invalid."""
    if not path.exists():
        return {}, None
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}, None
    if not isinstance(raw, dict):
        return {}, None
    nested_etags = raw.get("etags")
    if isinstance(nested_etags, dict):
        raw_mode = raw.get("mode")
        mode = raw_mode if raw_mode in ("sha1", "ntlm") else None
        return {str(k): v for k, v in nested_etags.items() if isinstance(v, str)}, mode
    return {str(k): v for k, v in raw.items() if isinstance(v, str)}, None


def _load_etags(path: Path) -> dict[str, str]:
    """Load a prefix -> ETag mapping from JSON, returning {} if missing or invalid."""
    return _load_index(path)[0]


def _save_etags(path: Path, etags: dict[str, str], *, mode: str | None = None) -> None:
    """Atomically persist a prefix -> ETag mapping (with optional hash mode) as compact JSON."""
    sorted_etags = dict(sorted(etags.items()))
    payload: object = {"mode": mode, "etags": sorted_etags} if mode is not None else sorted_etags
    with _atomic_open(path) as handle:
        handle.write(json.dumps(payload, separators=(",", ":")))


def _retry_delay(attempt: int) -> float:
    """Compute capped exponential backoff delay without floating-point overflow."""
    return min(0.5 * (1 << min(attempt, 5)), 10.0)


@contextlib.contextmanager
def _atomic_open(target: Path) -> Iterator[IO[str]]:
    """Open a sibling temp file for writing and atomically replace `target` on success."""
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        dir=target.parent,
        prefix=f".{target.name}.",
        suffix=".tmp",
    )
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as handle:
            yield handle
        os.replace(tmp_path, target)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink(missing_ok=True)
        raise


def _merge_shards(
    output_path: Path,
    work_dir: Path,
    start_prefix: int,
    end_prefix: int,
) -> int:
    """Merge sorted shards into `output_path` atomically and return total hashes written."""
    hashes_written = 0
    with _atomic_open(output_path) as handle:
        for prefix_int in range(start_prefix, end_prefix):
            prefix = f"{prefix_int:05X}"
            shard_path = work_dir / prefix[:2] / f"{prefix}.txt"
            counts = _parse_range_response(shard_path.read_text(encoding="utf-8"))
            for suffix, count in sorted(counts.items()):
                handle.write(f"{prefix}{suffix}:{count}\r\n")
                hashes_written += 1
    return hashes_written


async def download_offline_db(
    output_path: Path,
    *,
    ntlm: bool = False,
    directory: bool = False,
    concurrency: int = 32,
    resume: bool = True,
    force: bool = False,
    overwrite: bool = True,
    etag_cache_path: Path | None = None,
    start_prefix: int = 0x00000,
    end_prefix: int = MAX_PREFIX_EXCLUSIVE,
    user_agent: str = DEFAULT_USER_AGENT,
    timeout: float = REQUEST_TIMEOUT,
    max_retries: int | None = MAX_RETRIES,
    proxy: str | None = None,
    client: httpx.AsyncClient | None = None,
    sleep: Callable[[float], Awaitable[None]] = asyncio.sleep,
    on_progress: Callable[[int, int], None] | None = None,
) -> DownloadStats:
    """Download an offline HIBP Pwned Passwords dump compatible with ``OfflinePasswordsClient``.

    In single-file mode (``directory=False``), downloads 5-character hash range shards into a
    resumable work directory (``.<output_path.name>.part``) and merges them in ascending
    lexicographical order into ``output_path`` using an atomic file replacement.

    In directory mode (``directory=True``), writes flat ``00000.txt``..``FFFFF.txt`` range files
    directly under ``output_path`` and stores prefix ETags in ``DEFAULT_INDEX_FILENAME`` (or
    ``etag_cache_path`` if specified) so subsequent runs perform conditional HTTP 304 refreshes.

    Setting ``force=True`` ignores cached shards and saved ETags, forcing a full re-download and
    rebuilding any ETag index. Setting ``max_retries=None`` retries transient errors indefinitely.
    """
    _validate_options(
        concurrency=concurrency,
        max_retries=max_retries,
        start_prefix=start_prefix,
        end_prefix=end_prefix,
    )

    index_path: Path | None
    dir_index: Path | None = None
    if directory:
        if output_path.exists() and not output_path.is_dir():
            raise FileExistsError(f"Output path is an existing file: {output_path}")
        resolved_index = (
            etag_cache_path if etag_cache_path is not None else output_path / DEFAULT_INDEX_FILENAME
        )
        if (
            output_path.is_dir()
            and any(output_path.iterdir())
            and not resolved_index.exists()
            and not overwrite
        ):
            raise FileExistsError(
                f"Output directory is not empty and has no saved index: {output_path} "
                "(use --overwrite to replace)"
            )
        index_path = resolved_index
        dir_index = resolved_index
    else:
        if output_path.is_dir():
            raise IsADirectoryError(f"Output path is a directory: {output_path}")
        if not overwrite and output_path.exists():
            raise FileExistsError(
                f"Output file already exists: {output_path} (use --overwrite to replace)"
            )
        index_path = etag_cache_path

    requested_mode = "ntlm" if ntlm else "sha1"
    index_mode: str | None = requested_mode if directory else None
    existing_etags, existing_mode = (
        _load_index(index_path) if index_path is not None else ({}, None)
    )
    if (
        directory
        and existing_mode is not None
        and existing_mode != requested_mode
        and resume
        and not force
    ):
        raise ValueError(
            f"Offline directory {output_path} contains {existing_mode.upper()} hashes; "
            f"requested {requested_mode.upper()} mode "
            "(use --force-refresh or --no-resume to rebuild)"
        )

    started = time.monotonic()
    work_dir = output_path.parent / f".{output_path.name}.part"
    if not directory and (not resume or force) and work_dir.exists():
        shutil.rmtree(work_dir)

    etags: dict[str, str] = {} if (force or not resume) else existing_etags
    if dir_index is not None and (not dir_index.exists() or force or not resume):
        _save_etags(dir_index, etags, mode=index_mode)
    params: dict[str, str] = {"mode": "ntlm"} if ntlm else {}
    total_prefixes = end_prefix - start_prefix

    prefixes_downloaded = 0
    prefixes_cached = 0
    hashes_written = 0
    dirty_etags = 0
    completed = 0

    owns_client = client is None
    active_client = (
        client
        if client is not None
        else httpx.AsyncClient(
            base_url=BASE_URL,
            headers={"User-Agent": user_agent},
            timeout=timeout,
            proxy=proxy,
        )
    )

    async def _process_prefix(prefix_int: int) -> None:
        nonlocal prefixes_downloaded, prefixes_cached, hashes_written, dirty_etags, completed
        prefix = f"{prefix_int:05X}"
        shard_path = (
            output_path / f"{prefix}.txt" if directory else work_dir / prefix[:2] / f"{prefix}.txt"
        )

        if resume and not force and shard_path.exists() and index_path is None:
            prefixes_cached += 1
        else:
            headers: dict[str, str] = {}
            if resume and not force and shard_path.exists():
                cached_etag = etags.get(prefix)
                if cached_etag is not None:
                    headers["If-None-Match"] = cached_etag

            attempt = 0
            while True:
                try:
                    resp = await active_client.get(
                        f"/range/{prefix}",
                        headers=headers,
                        params=params,
                    )
                except httpx.RequestError as exc:
                    if max_retries is None or attempt < max_retries:
                        await sleep(_retry_delay(attempt))
                        attempt += 1
                        continue
                    raise HIBPError(f"Request failed for prefix {prefix}: {exc}") from exc

                if resp.status_code == 304 and "If-None-Match" in headers:
                    prefixes_cached += 1
                    break
                if resp.status_code == 429 or resp.status_code >= 500:
                    if max_retries is None or attempt < max_retries:
                        await sleep(_retry_delay(attempt))
                        attempt += 1
                        continue
                    raise HIBPError(f"HTTP {resp.status_code} for prefix {prefix}")
                if resp.status_code != 200:
                    raise HIBPError(f"HTTP {resp.status_code} for prefix {prefix}")

                with _atomic_open(shard_path) as handle:
                    handle.write(resp.text)
                if directory:
                    hashes_written += len(_parse_range_response(resp.text))
                new_etag = resp.headers.get("etag")
                if new_etag:
                    etags[prefix] = new_etag
                    dirty_etags += 1
                    if index_path is not None and dirty_etags >= ETAG_CHECKPOINT_INTERVAL:
                        _save_etags(index_path, etags, mode=index_mode)
                        dirty_etags = 0
                prefixes_downloaded += 1
                break

        completed += 1
        if on_progress is not None:
            on_progress(completed, total_prefixes)

    prefix_iter = iter(range(start_prefix, end_prefix))

    async def _worker() -> None:
        for prefix_int in prefix_iter:
            await _process_prefix(prefix_int)

    try:
        worker_count = min(concurrency, total_prefixes)
        workers = [asyncio.create_task(_worker()) for _ in range(worker_count)]
        try:
            await asyncio.gather(*workers)
        except BaseException:
            for worker in workers:
                worker.cancel()
            await asyncio.gather(*workers, return_exceptions=True)
            raise
    finally:
        if owns_client:
            await active_client.aclose()
        if index_path is not None:
            _save_etags(index_path, etags, mode=index_mode)

    if not directory:
        hashes_written = _merge_shards(output_path, work_dir, start_prefix, end_prefix)

    if index_path is None:
        # Without ETag revalidation, shards are no longer needed once merged.
        shutil.rmtree(work_dir)

    elapsed = max(0.0, time.monotonic() - started)
    ranges_per_second = round(total_prefixes / elapsed, 2) if elapsed > 0.0 else 0.0

    return DownloadStats(
        prefixes_total=total_prefixes,
        prefixes_downloaded=prefixes_downloaded,
        prefixes_cached=prefixes_cached,
        hashes_written=hashes_written,
        elapsed_seconds=elapsed,
        ranges_per_second=ranges_per_second,
        output_path=str(output_path),
        ntlm=ntlm,
        directory=directory,
    )
